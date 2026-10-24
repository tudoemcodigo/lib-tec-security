using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect.Internal;
using TEC.Security.Tokens;
using TEC.Vault.Abstractions;
using JwtTokenValidatedContext = Microsoft.AspNetCore.Authentication.JwtBearer.TokenValidatedContext;
using OidcTokenValidatedContext = Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext;

namespace TEC.Security.OpenIdConnect;

/// <summary>Métodos de extensão para registro do provedor OpenID Connect agnóstico.</summary>
public static class OpenIdConnectExtensions
{
    // ================================================================ API (JWT Bearer)

    /// <summary>Protege a API com access tokens OpenID Connect lidos de uma seção de configuração.</summary>
    public static SecurityBuilder AddOpenIdConnectApi(this SecurityBuilder builder, string scheme, IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(section);
        return builder.AddOpenIdConnectApi(scheme, o =>
        {
            o.Authority = section["Authority"] ?? string.Empty;
            o.Audience = section["Audience"];
            if (bool.TryParse(section["RequireHttpsMetadata"], out bool https))
                o.RequireHttpsMetadata = https;
            if (bool.TryParse(section["MultiTenant"], out bool multi))
                o.MultiTenant = multi;
            o.TenantClaim = section["TenantClaim"];
            if (section["RoleClaimType"] is { } rct)
                o.RoleClaimType = rct;
            if (section["NameClaimType"] is { } nct)
                o.NameClaimType = nct;

            var audiences = section.GetSection("Audiences").GetChildren();
            foreach (var aud in audiences)
            {
                if (!string.IsNullOrWhiteSpace(aud.Value))
                    o.Audiences.Add(aud.Value);
            }
        });
    }

    /// <summary>
    /// Protege a API com access tokens JWT de qualquer provedor OpenID Connect padrão (Keycloak, Auth0, Okta, Google, Entra ID, etc.),
    /// com descoberta automática de chaves JWKS e validação endurecida.
    /// </summary>
    public static SecurityBuilder AddOpenIdConnectApi(this SecurityBuilder builder, string scheme, Action<OpenIdConnectApiOptions> configure) =>
        AddOpenIdConnectApiCore(builder, scheme, configure, testSigningKeys: null);

    internal static SecurityBuilder AddOpenIdConnectApiCore(SecurityBuilder builder, string scheme, Action<OpenIdConnectApiOptions> configure,
        IList<SecurityKey>? testSigningKeys)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new OpenIdConnectApiOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.Authority))
            throw new InvalidOperationException($"OpenID Connect '{scheme}': Authority é obrigatória.");

        string[] audiences;
        if (options.Audiences.Count > 0)
            audiences = [.. options.Audiences];
        else if (!string.IsNullOrWhiteSpace(options.Audience))
            audiences = [options.Audience];
        else
            throw new InvalidOperationException($"OpenID Connect '{scheme}': informe ao menos uma audiência esperada (Audience ou Audiences).");

        return builder.AddJwtBearerProvider(new JwtProviderDefinition
        {
            Scheme = scheme,
            Provider = OpenIdConnectIdentity.ProviderName,
            CanHandle = jwt =>
            {
                if (jwt.Issuer is null)
                    return false;

                string authTrimmed = options.Authority.TrimEnd('/');
                string issTrimmed = jwt.Issuer.TrimEnd('/');
                if (!issTrimmed.Equals(authTrimmed, StringComparison.OrdinalIgnoreCase) && !options.MultiTenant)
                    return false;

                return jwt.Audiences.Any(a => audiences.Contains(a, StringComparer.OrdinalIgnoreCase));
            },
            CreateIdentity = (JwtTokenValidatedContext ctx, JsonWebToken token, out string reason) =>
            {
                var tenantRegistry = ctx.HttpContext.RequestServices.GetService<ITenantRegistry>();
                return OpenIdConnectIdentity.FromClaims(scheme, [.. token.Claims], options, tenantRegistry, out reason);
            },
            Configure = (jwtOptions, sp) =>
            {
                jwtOptions.Authority = options.Authority;
                jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;
                jwtOptions.TokenValidationParameters.ValidIssuers = [options.Authority.TrimEnd('/'), options.Authority.TrimEnd('/') + "/"];
                jwtOptions.TokenValidationParameters.ValidAudiences = audiences;

                if (options.ValidAlgorithms.Count > 0)
                {
                    jwtOptions.TokenValidationParameters.ValidAlgorithms = [.. options.ValidAlgorithms];
                }

                if (testSigningKeys is { } keys)
                {
                    var config = new OpenIdConnectConfiguration();
                    foreach (var key in keys)
                        config.SigningKeys.Add(key);

                    jwtOptions.Configuration = config;
                }
            }
        });
    }

    // ================================================================ Login Web (OIDC)

    /// <summary>Adiciona login web interativo baseado em OpenID Connect (Authorization Code + PKCE).</summary>
    public static SecurityBuilder AddOpenIdConnectWebLogin(this SecurityBuilder builder, string scheme, Action<OpenIdConnectWebLoginOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new OpenIdConnectWebLoginOptions();
        configure(options);

        if (string.IsNullOrWhiteSpace(options.Authority))
            throw new InvalidOperationException($"OpenID Connect WebLogin '{scheme}': Authority é obrigatória.");
        if (string.IsNullOrWhiteSpace(options.ClientId))
            throw new InvalidOperationException($"OpenID Connect WebLogin '{scheme}': ClientId é obrigatório.");

        return builder.AddWebLoginProvider(new WebLoginDefinition
        {
            Scheme = scheme,
            Provider = OpenIdConnectIdentity.ProviderName,
            CreateIdentity = (OidcTokenValidatedContext ctx, out string reason) =>
            {
                var apiOptions = new OpenIdConnectApiOptions { Authority = options.Authority };
                var tenantRegistry = ctx.HttpContext.RequestServices.GetService<ITenantRegistry>();
                return OpenIdConnectIdentity.FromClaims(scheme, [.. ctx.Principal!.Claims], apiOptions, tenantRegistry, out reason);
            },
            Configure = (oidcOptions, sp) =>
            {
                oidcOptions.Authority = options.Authority;
                oidcOptions.ClientId = options.ClientId;
                oidcOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;
                oidcOptions.ResponseType = OpenIdConnectResponseType.Code;

                if (!string.IsNullOrEmpty(options.ClientSecret))
                {
                    oidcOptions.ClientSecret = options.ClientSecret;
                }
                else if (!string.IsNullOrEmpty(options.ClientSecretName))
                {
                    var secretReader = sp.GetService<ISecretReader>();
                    if (secretReader is not null)
                    {
                        var secretResult = secretReader.GetSecretAsync(options.ClientSecretName).GetAwaiter().GetResult();
                        oidcOptions.ClientSecret = secretResult.IsSuccess ? secretResult.Value.Value : null;
                    }
                }

                oidcOptions.Scope.Clear();
                oidcOptions.Scope.Add("openid");
                foreach (string scope in options.Scopes)
                    oidcOptions.Scope.Add(scope);
            }
        });
    }

    // ================================================================ Cliente M2M (Client Credentials)

    /// <summary>Registra o provedor de tokens M2M para chamadas de serviço a serviço.</summary>
    public static SecurityBuilder AddOpenIdConnectClient(this SecurityBuilder builder, Action<OpenIdConnectClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.AddHttpClient<IAccessTokenProvider, OpenIdConnectAccessTokenProvider>((sp, client) => { });
        builder.Services.AddSingleton(sp =>
        {
            var options = new OpenIdConnectClientOptions();
            configure(options);
            var httpClientFactory = sp.GetRequiredService<IHttpClientFactory>();
            var httpClient = httpClientFactory.CreateClient("OpenIdConnect.M2M");
            var secretReader = sp.GetService<ISecretReader>();
            var time = sp.GetService<TimeProvider>() ?? TimeProvider.System;
            return new OpenIdConnectAccessTokenProvider(httpClient, options, secretReader, time);
        });

        return builder;
    }

    /// <summary>Anexa o token de serviço M2M do OpenID Connect a um <see cref="IHttpClientBuilder"/> para os hosts autorizados.</summary>
    public static IHttpClientBuilder AddOpenIdConnectAccessToken(this IHttpClientBuilder clientBuilder, Action<AccessTokenHandlerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(clientBuilder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AccessTokenHandlerOptions();
        configure(options);
        options.Validate();

        return clientBuilder.AddHttpMessageHandler(sp =>
        {
            var provider = sp.GetRequiredService<IAccessTokenProvider>();
            return new AccessTokenHandler(provider, options);
        });
    }
}
