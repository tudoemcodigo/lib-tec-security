using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
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
    /// <summary>Nome do <c>HttpClient</c> do cliente M2M (endpoint de token), sem seguir redirecionamentos.</summary>
    internal const string M2MHttpClientName = "OpenIdConnect.M2M";

    // ================================================================ API (JWT Bearer)

    /// <summary>
    /// Protege a API com access tokens OpenID Connect lidos de uma seção de configuração (<c>Authority</c>, <c>Audience</c>,
    /// <c>Audiences</c>, <c>RequireHttpsMetadata</c>, <c>MultiTenant</c>, <c>TenantClaim</c>, <c>RoleClaimType</c>,
    /// <c>NameClaimType</c> e <c>Kind</c>). Listas de <c>Kind</c> presentes na seção substituem as do padrão.
    /// </summary>
    /// <exception cref="InvalidOperationException">Valor de <c>Kind</c> inválido, além dos erros do registro em código.</exception>
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

            ReadKind(section.GetSection("Kind"), o.Kind, scheme);
        });
    }

    /// <summary>
    /// Protege a API com access tokens JWT de qualquer provedor OpenID Connect padrão (Keycloak, Auth0, Okta, Google, Entra ID, etc.),
    /// com descoberta automática de chaves JWKS e validação endurecida.
    /// </summary>
    /// <exception cref="InvalidOperationException">Sem <c>Authority</c>, sem audiência ou regra de <c>Kind</c> inválida.</exception>
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

        // Regras de Kind conferidas no registro: regra inválida impede a subida
        var classifier = KindClassifier.Create(options, scheme);

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
                bool issuerMatches = issTrimmed.Equals(authTrimmed, StringComparison.OrdinalIgnoreCase);

                if (!issuerMatches)
                {
                    if (!options.MultiTenant)
                        return false;

                    if (options.ValidIssuers.Count > 0 &&
                        !options.ValidIssuers.Any(i => i.TrimEnd('/').Equals(issTrimmed, StringComparison.OrdinalIgnoreCase)))
                    {
                        return false;
                    }
                }

                return jwt.Audiences.Any(a => audiences.Contains(a, StringComparer.OrdinalIgnoreCase));
            },
            CreateIdentity = (JwtTokenValidatedContext ctx, JsonWebToken token, out string reason) =>
            {
                var tenantRegistry = ctx.HttpContext.RequestServices.GetService<ITenantRegistry>();
                return OpenIdConnectIdentity.FromClaims(scheme, [.. token.Claims], options, classifier, tenantRegistry, out reason);
            },
            Configure = (jwtOptions, sp) =>
            {
                jwtOptions.Authority = options.Authority;
                jwtOptions.RequireHttpsMetadata = options.RequireHttpsMetadata;

                var issuers = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    options.Authority.TrimEnd('/'),
                    options.Authority.TrimEnd('/') + "/"
                };
                foreach (var iss in options.ValidIssuers)
                {
                    if (!string.IsNullOrWhiteSpace(iss))
                    {
                        issuers.Add(iss.TrimEnd('/'));
                        issuers.Add(iss.TrimEnd('/') + "/");
                    }
                }
                jwtOptions.TokenValidationParameters.ValidIssuers = issuers;
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

    /// <summary>
    /// Adiciona login web interativo baseado em OpenID Connect (Authorization Code + PKCE). A identidade é sempre de usuário e,
    /// em <c>resource_access</c> (Keycloak), só os papéis do próprio <see cref="OpenIdConnectWebLoginOptions.ClientId"/> entram.
    /// </summary>
    /// <remarks>
    /// Com <see cref="OpenIdConnectWebLoginOptions.ClientSecretName"/>, o segredo é conferido na subida e lido do TEC.Vault de novo
    /// a cada login (troca do código e pedido por PAR), sem ficar guardado nas opções: a rotação no cofre vale sem reiniciar. Para
    /// isso o provedor usa os delegates <c>OnAuthorizationCodeReceived</c> e <c>OnPushAuthorization</c> dos eventos do esquema;
    /// não os substitua.
    /// </remarks>
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
                var tenantRegistry = ctx.HttpContext.RequestServices.GetService<ITenantRegistry>();
                return OpenIdConnectIdentity.FromWebLogin(scheme, [.. ctx.Principal!.Claims], options, tenantRegistry, out reason);
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
                    var secretReader = sp.GetService<ISecretReader>()
                        ?? throw new InvalidOperationException($"OpenID Connect WebLogin '{scheme}': ClientSecretName '{options.ClientSecretName}' informado, mas nenhum ISecretReader está registrado.");
                    UseClientSecretFromVault(oidcOptions, secretReader, options.ClientSecretName, scheme);
                }

                oidcOptions.Scope.Clear();
                oidcOptions.Scope.Add("openid");
                foreach (string scope in options.Scopes)
                    oidcOptions.Scope.Add(scope);
            }
        });
    }

    /// <summary>
    /// Segredo do cofre lido na hora de usar: conferido uma vez aqui (configuração errada impede a subida) e lido de novo a cada
    /// troca do código e a cada pedido por PAR. O valor nunca fica em <see cref="OpenIdConnectOptions.ClientSecret"/>.
    /// </summary>
    private static void UseClientSecretFromVault(OpenIdConnectOptions oidcOptions, ISecretReader secretReader, string secretName, string scheme)
    {
        _ = ReadClientSecretAsync(secretReader, secretName, scheme, CancellationToken.None).GetAwaiter().GetResult();

        oidcOptions.Events.OnAuthorizationCodeReceived = async context =>
        {
            string secret = await ReadClientSecretAsync(secretReader, secretName, scheme, context.HttpContext.RequestAborted).ConfigureAwait(false);
            if (context.TokenEndpointRequest is { } request)
                request.ClientSecret = secret;
        };

        // PAR (.NET 9+, usado quando o IdP anuncia o endpoint, como o Keycloak): o handler só enviaria o ClientSecret das opções
        oidcOptions.Events.OnPushAuthorization = async context =>
        {
            context.ProtocolMessage.ClientSecret =
                await ReadClientSecretAsync(secretReader, secretName, scheme, context.HttpContext.RequestAborted).ConfigureAwait(false);
            context.HandleClientAuthentication();
        };
    }

    private static async Task<string> ReadClientSecretAsync(ISecretReader secretReader, string secretName, string scheme, CancellationToken cancellationToken)
    {
        var secretResult = await secretReader.GetSecretAsync(secretName, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!secretResult.IsSuccess || secretResult.Value is null || string.IsNullOrEmpty(secretResult.Value.Value))
            throw new InvalidOperationException($"OpenID Connect WebLogin '{scheme}': falha ao obter o segredo '{secretName}' do cofre TEC.Vault.");

        return secretResult.Value.Value;
    }

    // ================================================================ Cliente M2M (Client Credentials)

    /// <summary>Registra o provedor de tokens M2M para chamadas de serviço a serviço (um cliente por aplicação).</summary>
    /// <remarks>
    /// <para>As opções são validadas na subida do host (<c>ValidateOnStart</c>): configuração errada ou insegura (ver
    /// <see cref="OpenIdConnectClientOptions"/>) impede a aplicação de subir.</para>
    /// <para>O <c>HttpClient</c> do endpoint de token não segue redirecionamentos: o client secret vai no corpo do POST, e um
    /// 307/308 o reenviaria a outro destino. Uma resposta 3xx é tratada como falha. As conexões são recicladas a cada 2 minutos
    /// (o cliente vive no Singleton), para acompanhar troca de DNS do IdP.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez.</exception>
    public static SecurityBuilder AddOpenIdConnectClient(this SecurityBuilder builder, Action<OpenIdConnectClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        if (builder.Properties.ContainsKey(typeof(OpenIdConnectClientOptions)))
            throw new InvalidOperationException("AddOpenIdConnectClient já foi chamado: registre um único cliente M2M por aplicação.");
        builder.Properties[typeof(OpenIdConnectClientOptions)] = M2MHttpClientName;

        builder.Services.AddOptions<OpenIdConnectClientOptions>().Configure(configure).ValidateOnStart();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<OpenIdConnectClientOptions>, OpenIdConnectClientOptionsValidator>());

        // O provedor é Singleton e guarda o HttpClient: a renovação de handlers do IHttpClientFactory não o alcança, então as
        // conexões são recicladas pelo próprio handler (PooledConnectionLifetime) para acompanhar troca de DNS do IdP
        builder.Services.AddHttpClient(M2MHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                PooledConnectionLifetime = TimeSpan.FromMinutes(2)
            });

        builder.Services.AddSingleton(sp => new OpenIdConnectAccessTokenProvider(
            sp.GetRequiredService<IHttpClientFactory>().CreateClient(M2MHttpClientName),
            sp.GetRequiredService<IOptions<OpenIdConnectClientOptions>>().Value,
            sp.GetService<ISecretReader>(),
            sp.GetService<TimeProvider>() ?? TimeProvider.System,
            sp.GetService<ILogger<OpenIdConnectAccessTokenProvider>>()));
        builder.Services.AddSingleton<IAccessTokenProvider>(sp => sp.GetRequiredService<OpenIdConnectAccessTokenProvider>());

        return builder;
    }

    /// <summary>Anexa o token de serviço M2M do OpenID Connect a um <see cref="IHttpClientBuilder"/> para os hosts autorizados.</summary>
    /// <remarks>Requisições para destinos fora de <c>AllowedHosts</c> (ou sem HTTPS) são bloqueadas com o log 3121.</remarks>
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
            return new AccessTokenHandler(provider, options, sp.GetService<ILogger<AccessTokenHandler>>());
        });
    }

    // ================================================================ apoio

    /// <summary>Lê a subseção <c>Kind</c>; listas presentes substituem as do padrão. Valor inválido impede a subida.</summary>
    internal static void ReadKind(IConfigurationSection section, OpenIdConnectKindOptions kind, string scheme)
    {
        if (!section.Exists())
            return;

        if (section.GetSection("ApplicationClaims").Exists())
            kind.ApplicationClaims = [.. section.GetSection("ApplicationClaims").GetChildren().Select(c => c.Value ?? string.Empty)];
        if (section.GetSection("UserClaims").Exists())
            kind.UserClaims = [.. section.GetSection("UserClaims").GetChildren().Select(c => c.Value ?? string.Empty)];

        if (section["ApplicationWhenSubjectIsClient"] is { } subjectIsClient)
            kind.ApplicationWhenSubjectIsClient = ParseBool(subjectIsClient, "ApplicationWhenSubjectIsClient", scheme);
        if (section["UseEntraIdScpRule"] is { } entraId)
            kind.UseEntraIdScpRule = ParseBool(entraId, "UseEntraIdScpRule", scheme);
        if (section["Unresolved"] is { } unresolved)
        {
            if (!Enum.TryParse<OpenIdConnectUnresolvedKind>(unresolved, ignoreCase: true, out var parsed) || !Enum.IsDefined(parsed)
                || unresolved.Trim().All(char.IsAsciiDigit))
                throw new InvalidOperationException($"OpenID Connect '{scheme}': Kind:Unresolved deve ser Reject, User ou Application.");
            kind.Unresolved = parsed;
        }
    }

    private static bool ParseBool(string value, string key, string scheme) =>
        bool.TryParse(value, out bool parsed)
            ? parsed
            : throw new InvalidOperationException($"OpenID Connect '{scheme}': Kind:{key} deve ser true ou false.");
}

/// <summary>Validação das opções do cliente M2M na subida (<c>ValidateOnStart</c>) e na primeira leitura.</summary>
internal sealed class OpenIdConnectClientOptionsValidator(IServiceProvider services) : IValidateOptions<OpenIdConnectClientOptions>
{
    public ValidateOptionsResult Validate(string? name, OpenIdConnectClientOptions options)
    {
        try
        {
            OpenIdConnectAccessTokenProvider.ValidateOptions(options);
        }
        catch (Exception exception) when (exception is InvalidOperationException or NotSupportedException)
        {
            return ValidateOptionsResult.Fail(exception.Message);
        }

        if (string.IsNullOrEmpty(options.ClientSecret) && !string.IsNullOrEmpty(options.ClientSecretName) && !HasSecretReader())
            return ValidateOptionsResult.Fail("OpenIdConnectClientOptions: ClientSecretName informado, mas nenhum ISecretReader (TEC.Vault) está registrado.");

        return ValidateOptionsResult.Success;
    }

    // Sem instanciar o leitor quando o container sabe responder se o serviço existe
    private bool HasSecretReader() =>
        services.GetService<IServiceProviderIsService>() is { } isService
            ? isService.IsService(typeof(ISecretReader))
            : services.GetService<ISecretReader>() is not null;
}
