using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TEC.Vault.Providers;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.DependencyInjection;
using TEC.Security.EntraId.Internal;
using TEC.Core.Threading;
using TEC.Security.Tokens;
using TEC.Security.Resilience;
using JwtTokenValidatedContext = Microsoft.AspNetCore.Authentication.JwtBearer.TokenValidatedContext;
using OidcTokenValidatedContext = Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext;

namespace TEC.Security.EntraId;

/// <summary>Registro do provedor Microsoft Entra ID.</summary>
public static class EntraIdExtensions
{
    /// <summary>Seção sugerida das configurações do Entra ID.</summary>
    public const string SectionName = "Security:EntraId";

    // ================================================================ API (tokens bearer)

    /// <summary>Protege a API com tokens do Entra ID lidos de <paramref name="section"/> (ex.: <c>Security:EntraId:Api</c>).</summary>
    public static SecurityBuilder AddEntraIdApi(this SecurityBuilder builder, string scheme, IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(section);
        return builder.AddEntraIdApi(scheme, o => section.Bind(o));
    }

    /// <summary>
    /// Protege a API com access tokens do Entra ID: emissor exato do tenant (só tenants liberados), audiência da API, RS256,
    /// <c>scp</c> ou <c>roles</c> obrigatório (ID token recusado), aplicações cliente opcionais e normalização da identidade
    /// (<c>oid</c> como id, <c>tid</c> → tenant do cadastro, <c>roles</c> → papéis/permissões, <c>scp</c> → escopos).
    /// </summary>
    /// <exception cref="InvalidOperationException">Opções inválidas (validadas aqui, na inicialização).</exception>
    /// <example>
    /// <code>
    /// builder.Services.AddTecSecurity(builder.Configuration, security =&gt; security
    ///     .AddAspNetCore()
    ///     .AddEntraIdApi("Funcionarios", builder.Configuration.GetSection("Security:EntraId:Api")));
    /// </code>
    /// </example>
    public static SecurityBuilder AddEntraIdApi(this SecurityBuilder builder, string scheme, Action<EntraIdApiOptions> configure) =>
        AddEntraIdApiCore(builder, scheme, configure, testSigningKeys: null);

    /// <summary>Registro da API; <paramref name="testSigningKeys"/> só em testes automatizados (chaves no lugar do JWKS, sem rede).</summary>
    internal static SecurityBuilder AddEntraIdApiCore(SecurityBuilder builder, string scheme, Action<EntraIdApiOptions> configure,
        IList<SecurityKey>? testSigningKeys)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new EntraIdApiOptions();
        configure(options);
        var cloud = ValidateApp(options, $"Entra ID '{scheme}'");

        if (options.AllowedClientApplications.Any(id => !EntraIdCloud.IsGuid(id)))
            throw new InvalidOperationException($"Entra ID '{scheme}': AllowedClientApplications deve conter GUIDs.");
        if (options.Audiences.Any(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException($"Entra ID '{scheme}': Audiences não pode ter valor vazio.");

        string[] audiences = options.Audiences.Count > 0 ? [.. options.Audiences] : [options.ClientId!, $"api://{options.ClientId}"];
        var recognizer = new EntraIdTenantPolicy(cloud, options, options.AcceptV1Tokens, registry: null);

        return builder.AddJwtBearerProvider(new JwtProviderDefinition
        {
            Scheme = scheme,
            Provider = EntraIdTenantPolicy.ProviderName,
            CanHandle = jwt => recognizer.LooksLikeIssuer(jwt) && jwt.Audiences.Any(a => audiences.Contains(a, StringComparer.Ordinal)),
            CreateIdentity = (JwtTokenValidatedContext _, JsonWebToken token, out string reason) =>
                EntraIdIdentity.FromAccessToken(scheme, [.. token.Claims], options, out reason),
            Configure = (o, sp) =>
            {
                var policy = new EntraIdTenantPolicy(cloud, options, options.AcceptV1Tokens, sp.GetRequiredService<ITenantRegistry>());
                if (options.MultiTenant && sp.GetRequiredService<IOptionsMonitor<Configuration.SecurityOptions>>().CurrentValue.RolesAsPermissions)
                    EntraIdLog.MultiTenantRolesAsPermissions(sp.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.EntraId"), scheme);
                o.Authority = cloud.Authority(options.MultiTenant ? "organizations" : options.TenantId!);
                o.TokenValidationParameters.ValidAudiences = audiences;
                o.TokenValidationParameters.IssuerValidator = policy.ValidateIssuer;
                o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256];

                if (testSigningKeys is { } keys)
                {
                    var configuration = new OpenIdConnectConfiguration();
                    foreach (var key in keys)
                        configuration.SigningKeys.Add(key);
                    o.Configuration = configuration;
                }
            }
        });
    }

    // ================================================================ login web (OIDC)

    /// <summary>Login web com o Entra ID lido de <paramref name="section"/> (ex.: <c>Security:EntraId:WebLogin</c>).</summary>
    public static SecurityBuilder AddEntraIdWebLogin(this SecurityBuilder builder, string scheme, IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(section);
        return builder.AddEntraIdWebLogin(scheme, o => section.Bind(o));
    }

    /// <summary>
    /// Login web (MVC, Razor Pages, Blazor) com o Entra ID: Authorization Code + PKCE, credencial da aplicação sem segredo na
    /// configuração (<see cref="EntraIdWebLoginOptions.Credential"/>), tenants liberados como na API e sessão revalidada.
    /// Mapeie as rotas com <c>app.MapTecWebLogin()</c>.
    /// </summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public static SecurityBuilder AddEntraIdWebLogin(this SecurityBuilder builder, string scheme, Action<EntraIdWebLoginOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new EntraIdWebLoginOptions();
        configure(options);
        var cloud = ValidateApp(options, $"Entra ID '{scheme}'");
        EntraIdClientCredential.Validate(options.Credential, options.TenantId, options.ClientId,
            VaultEnvironment.FindHostEnvironment(builder.Services), requireClientAuthentication: true, $"Entra ID '{scheme}'");
        if (options.MultiTenant && options.Credential.Type == EntraIdCredentialType.ManagedIdentityFederation && options.TenantId is null)
            throw new InvalidOperationException($"Entra ID '{scheme}': informe TenantId (tenant da app registration).");
        if (!IsLocalPath(options.CallbackPath) || !IsLocalPath(options.SignedOutCallbackPath))
            throw new InvalidOperationException($"Entra ID '{scheme}': CallbackPath e SignedOutCallbackPath devem ser caminhos locais (ex.: /signin-oidc).");

        return builder.AddWebLoginProvider(new WebLoginDefinition
        {
            Scheme = scheme,
            Provider = EntraIdTenantPolicy.ProviderName,
            RevalidationInterval = options.RevalidationInterval,
            MaxSessionLifetime = options.MaxSessionLifetime,
            // Tenant do Entra ID ainda liberado (cadastro ou AllowedTenantIds), conferido a cada revalidação da sessão
            IsSessionAllowed = (user, sp) => new EntraIdTenantPolicy(cloud, options, acceptV1: false, sp.GetRequiredService<ITenantRegistry>())
                .IsTenantAllowed(user.ExternalTenantId),
            CreateIdentity = (OidcTokenValidatedContext context, out string reason) =>
                EntraIdIdentity.FromIdToken(scheme, [.. context.Principal?.Claims ?? []], out reason),
            ConfigureCookie = cookie => cookie.ExpireTimeSpan = options.SessionDuration,
            Configure = (o, sp) =>
            {
                var policy = new EntraIdTenantPolicy(cloud, options, acceptV1: false, sp.GetRequiredService<ITenantRegistry>());
                string tenantSegment = options.MultiTenant ? "organizations" : options.TenantId!;
                var credential = new EntraIdClientCredential(cloud, options.TenantId, options.ClientId, options.Credential, sp);
                var logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.EntraId.WebLogin");

                o.Authority = cloud.Authority(tenantSegment);
                o.ClientId = options.ClientId;
                o.CallbackPath = options.CallbackPath;
                o.SignedOutCallbackPath = options.SignedOutCallbackPath;
                o.TokenValidationParameters.ValidAudience = options.ClientId;
                o.TokenValidationParameters.IssuerValidator = policy.ValidateIssuer;
                o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256];

                o.Events ??= new OpenIdConnectEvents();
                o.Events.OnAuthorizationCodeReceived = async context =>
                {
                    string tokenEndpoint = context.Options.Configuration?.TokenEndpoint ?? cloud.TokenEndpoint(tenantSegment);
                    ClientAuthentication client;
                    try
                    {
                        client = await credential.GetClientAuthenticationAsync(tokenEndpoint, context.HttpContext.RequestAborted).ConfigureAwait(false);
                    }
                    catch (Exception exception) when (exception is not OperationCanceledException)
                    {
                        EntraIdLog.CodeRedemptionCredentialFailed(logger, exception, scheme, exception.GetType().Name);
                        context.Fail("Credencial da aplicação indisponível.");
                        return;
                    }

                    var request = context.TokenEndpointRequest!;
                    if (client.Secret is not null)
                        request.ClientSecret = client.Secret;
                    else
                    {
                        request.ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                        request.ClientAssertion = client.Assertion;
                    }
                };
            }
        });
    }

    // ================================================================ chamadas entre serviços

    /// <summary>Identidade da aplicação para chamar outros serviços, lida de <paramref name="section"/> (ex.: <c>Security:EntraId:Client</c>).</summary>
    public static SecurityBuilder AddEntraIdClient(this SecurityBuilder builder, IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(section);
        return builder.AddEntraIdClient(o => section.Bind(o));
    }

    /// <summary>
    /// Registra a identidade da aplicação no Entra ID: <see cref="IAccessTokenProvider"/> (client credentials, com cache) e a
    /// base do On-Behalf-Of. Use nos <c>HttpClient</c> com <c>AddEntraIdAccessToken</c> ou <c>AddEntraIdOnBehalfOf</c>.
    /// Funciona também em workers (sem ASP.NET Core no fluxo).
    /// </summary>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez ou opções inválidas.</exception>
    public static SecurityBuilder AddEntraIdClient(this SecurityBuilder builder, Action<EntraIdClientOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);
        if (builder.Properties.ContainsKey(typeof(EntraIdClientOptions)))
            throw new InvalidOperationException("AddEntraIdClient já foi chamado.");

        var options = new EntraIdClientOptions();
        configure(options);
        if (!EntraIdCloud.TryParse(options.Instance, out var cloud))
            throw new InvalidOperationException("Entra ID (cliente): Instance deve ser uma instância oficial do Entra ID (ex.: https://login.microsoftonline.com/).");
        EntraIdClientCredential.Validate(options.Credential, options.TenantId, options.ClientId,
            VaultEnvironment.FindHostEnvironment(builder.Services), requireClientAuthentication: false, "Entra ID (cliente)");
        (options.Resilience ?? throw new InvalidOperationException("Entra ID (cliente): Resilience é obrigatório.")).Validate("Entra ID (cliente)");

        builder.Properties[typeof(EntraIdClientOptions)] = options;

        var services = builder.Services;
        services.AddHttpClient(EntraIdTokenEndpoint.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(30));
        services.AddSingleton(sp => new EntraIdClientRegistration(cloud, options,
            new EntraIdClientCredential(cloud, options.TenantId, options.ClientId, options.Credential, sp),
            sp.GetService<TimeProvider>() ?? TimeProvider.System, sp.GetService<ILoggerFactory>()));
        services.AddSingleton(sp =>
        {
            var registration = sp.GetRequiredService<EntraIdClientRegistration>();
            return new EntraIdAccessTokenProvider(registration.Credential, sp.GetService<TimeProvider>(),
                sp.GetService<ILogger<EntraIdAccessTokenProvider>>(), registration.AccessTokenCircuit);
        });
        services.AddSingleton<IAccessTokenProvider>(sp => sp.GetRequiredService<EntraIdAccessTokenProvider>());
        return builder;
    }

    /// <summary>
    /// Anexa o token da aplicação (client credentials) às requisições deste <c>HttpClient</c>, só para
    /// <see cref="AccessTokenHandlerOptions.AllowedHosts"/> com HTTPS. Exige <see cref="AddEntraIdClient(SecurityBuilder, Action{EntraIdClientOptions})"/>.
    /// </summary>
    /// <example>
    /// <code>
    /// builder.Services.AddHttpClient&lt;EstoqueClient&gt;(c =&gt; c.BaseAddress = new Uri("https://estoque.contoso.com/"))
    ///     .AddEntraIdAccessToken(o =&gt;
    ///     {
    ///         o.Scopes.Add("api://&lt;client-id-do-estoque&gt;/.default");
    ///         o.AllowedHosts.Add("estoque.contoso.com");
    ///     });
    /// </code>
    /// </example>
    public static IHttpClientBuilder AddEntraIdAccessToken(this IHttpClientBuilder builder, Action<AccessTokenHandlerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AccessTokenHandlerOptions();
        configure(options);
        options.Validate();

        return builder.AddHttpMessageHandler(sp => new AccessTokenHandler(sp.GetRequiredService<EntraIdAccessTokenProvider>(), options,
            sp.GetService<ILogger<AccessTokenHandler>>()));
    }

    /// <summary>
    /// Troca o token do usuário da requisição atual por um token para o serviço de destino (On-Behalf-Of), só para
    /// <see cref="AccessTokenHandlerOptions.AllowedHosts"/> com HTTPS. A credencial é a de
    /// <see cref="AddEntraIdClient(SecurityBuilder, Action{EntraIdClientOptions})"/> (a app registration desta API).
    /// </summary>
    public static IHttpClientBuilder AddEntraIdOnBehalfOf(this IHttpClientBuilder builder, Action<AccessTokenHandlerOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new AccessTokenHandlerOptions();
        configure(options);
        options.Validate();

        builder.Services.AddHttpContextAccessor();
        return builder.AddHttpMessageHandler(sp =>
        {
            var registration = sp.GetRequiredService<EntraIdClientRegistration>();
            if (!registration.Credential.SupportsClientAuthentication || registration.Options.ClientId is null)
                throw new InvalidOperationException("On-Behalf-Of exige credencial da app registration em AddEntraIdClient (ManagedIdentityFederation, WorkloadIdentity, Certificate ou ClientSecret).");

            var time = sp.GetService<TimeProvider>() ?? TimeProvider.System;
            return new EntraIdOnBehalfOfHandler(sp.GetRequiredService<IHttpContextAccessor>(), registration.Credential,
                new EntraIdTokenEndpoint(sp.GetRequiredService<IHttpClientFactory>().CreateClient(EntraIdTokenEndpoint.HttpClientName), time,
                    registration.Options.Resilience, registration.OnBehalfOfCircuit),
                registration.Cloud, registration.Options.ClientId, options, registration.OnBehalfOfCache, registration.OnBehalfOfFlights,
                time, sp.GetRequiredService<ILogger<EntraIdOnBehalfOfHandler>>());
        });
    }

    // ================================================================ validação

    private static EntraIdCloud ValidateApp(EntraIdAppOptions options, string context)
    {
        void Require(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException($"{context}: {message}");
        }

        Require(EntraIdCloud.TryParse(options.Instance, out var cloud),
            "Instance deve ser uma instância oficial do Entra ID (ex.: https://login.microsoftonline.com/), sem caminho, porta ou query.");
        Require(EntraIdCloud.IsGuid(options.ClientId), "ClientId (GUID) é obrigatório.");
        Require(options.MultiTenant || EntraIdCloud.IsGuid(options.TenantId), "TenantId (GUID) é obrigatório sem MultiTenant.");
        Require(options.TenantId is null || EntraIdCloud.IsGuid(options.TenantId), "TenantId deve ser um GUID (nunca 'common' ou 'organizations').");
        Require(options.AllowedTenantIds.All(EntraIdCloud.IsGuid), "AllowedTenantIds deve conter GUIDs.");
        Require(options.MultiTenant || options.AllowedTenantIds.Count == 0, "AllowedTenantIds exige MultiTenant = true.");
        return cloud!;
    }

    private static bool IsLocalPath(string? path) => path is { Length: > 1 } && path[0] == '/' && path[1] != '/' && path[1] != '\\';
}

/// <summary>Identidade da aplicação registrada por <c>AddEntraIdClient</c>.</summary>
internal sealed class EntraIdClientRegistration(EntraIdCloud cloud, EntraIdClientOptions options, EntraIdClientCredential credential,
    TimeProvider? time = null, ILoggerFactory? loggerFactory = null) : IDisposable
{
    /// <summary>Circuit breaker dos tokens da aplicação (client credentials); <c>null</c> = desligado.</summary>
    public SecurityCircuitBreaker? AccessTokenCircuit { get; } = SecurityCircuitBreaker.Create(EntraIdTenantPolicy.ProviderName,
        options.Resilience.CircuitBreaker, timeProvider: time, logger: loggerFactory?.CreateLogger<EntraIdAccessTokenProvider>());

    /// <summary>
    /// Circuit breaker do On-Behalf-Of (singleton: os handlers são recriados pelo <c>IHttpClientFactory</c>). Só falhas
    /// transitórias do endpoint de token contam; <c>null</c> = desligado.
    /// </summary>
    public SecurityCircuitBreaker? OnBehalfOfCircuit { get; } = SecurityCircuitBreaker.Create(EntraIdTenantPolicy.ProviderName + ".OnBehalfOf",
        options.Resilience.CircuitBreaker, EntraIdTokenEndpoint.IsTransient, time, loggerFactory?.CreateLogger<EntraIdOnBehalfOfHandler>());

    public EntraIdCloud Cloud => cloud;

    public EntraIdClientOptions Options => options;

    public EntraIdClientCredential Credential => credential;

    /// <summary>Cache privado dos tokens On-Behalf-Of (limite de entradas).</summary>
    public MemoryCache OnBehalfOfCache { get; } = new(new MemoryCacheOptions { SizeLimit = 10_000 });

    /// <summary>Uma troca On-Behalf-Of por usuário + escopos em andamento: requisições simultâneas do mesmo usuário aguardam a mesma.</summary>
    public SingleFlight<string, AccessToken> OnBehalfOfFlights { get; } = new(StringComparer.Ordinal);

    public void Dispose() => OnBehalfOfCache.Dispose();
}
