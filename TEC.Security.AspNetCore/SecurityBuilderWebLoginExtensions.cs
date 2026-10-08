using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.AspNetCore.Internal;
using TEC.Security.Claims;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.Diagnostics;

namespace TEC.Security.AspNetCore;

/// <summary>Login web (OpenID Connect com Authorization Code + PKCE e cookie de sessão) para MVC, Razor Pages e Blazor.</summary>
public static class SecurityBuilderWebLoginExtensions
{
    /// <summary>Nome do cookie de sessão. O prefixo <c>__Host-</c> obriga o navegador a exigir HTTPS, <c>Path=/</c> e nenhum domínio.</summary>
    public const string CookieName = "__Host-TEC.Auth";

    internal const string ValidatedAtKey = ".tec.validated";
    internal const string SignedInAtKey = ".tec.signed_in";

    /// <summary>
    /// Registra um login web com os controles endurecidos: Authorization Code + PKCE (sem fluxo implícito), nonce e state
    /// validados, tokens não guardados no cookie, cookie <c>__Host-</c> HttpOnly/Secure/SameSite=Lax, sessão revalidada
    /// (tenant a cada requisição; tenant, permissões e regra do provedor a cada <see cref="WebLoginDefinition.RevalidationInterval"/>),
    /// duração máxima absoluta (<see cref="WebLoginDefinition.MaxSessionLifetime"/>) e 401/403 em vez de redirecionamento para
    /// chamadas de API (sem <c>Accept: text/html</c>). Uso pelos pacotes de provedor (ex.: <c>AddEntraIdWebLogin</c>).
    /// </summary>
    /// <remarks>
    /// <para>O cookie é protegido pelo Data Protection do ASP.NET Core: com mais de uma instância, persista as chaves em local
    /// compartilhado e protegido (ex.: <c>PersistKeysToAzureBlobStorage</c> + <c>ProtectKeysWithAzureKeyVault</c>).</para>
    /// <para>CSRF: <c>SameSite=Lax</c> bloqueia POSTs de outros sites com o cookie na maioria dos navegadores; em formulários use
    /// também o antiforgery do ASP.NET Core.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">Sem <c>AddAspNetCore</c> antes, segundo login web ou intervalos inválidos.</exception>
    public static SecurityBuilder AddWebLoginProvider(this SecurityBuilder builder, WebLoginDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(definition);

        if (definition.RevalidationInterval < TimeSpan.FromMinutes(1) || definition.RevalidationInterval > TimeSpan.FromHours(1))
            throw new InvalidOperationException("WebLoginDefinition.RevalidationInterval deve ficar entre 1 minuto e 1 hora.");
        if (definition.MaxSessionLifetime < TimeSpan.FromHours(1) || definition.MaxSessionLifetime > TimeSpan.FromHours(24))
            throw new InvalidOperationException("WebLoginDefinition.MaxSessionLifetime deve ficar entre 1 e 24 horas.");

        var schemes = builder.GetSchemes();
        schemes.SetCookie(definition.Scheme);
        if (!Common.SecurityRules.IsValidName(definition.ChallengeScheme))
            throw new InvalidOperationException("Nome de esquema inválido para o login web.");

        builder.Services.AddAuthentication()
            .AddCookie(definition.Scheme, _ => { })
            .AddOpenIdConnect(definition.ChallengeScheme, _ => { });

        // Os controles obrigatórios são conferidos por SecurityOptionsValidators, depois de qualquer PostConfigure
        builder.Services.AddOptions<CookieAuthenticationOptions>(definition.Scheme)
            .Configure(o =>
            {
                ApplyCookieDefaults(o, definition);
                definition.ConfigureCookie?.Invoke(o);
            });

        builder.Services.AddOptions<OpenIdConnectOptions>(definition.ChallengeScheme)
            .Configure<IServiceProvider>((o, sp) =>
            {
                ApplyOidcDefaults(o, definition);
                definition.Configure?.Invoke(o, sp);
            });

        return builder;
    }

    // ---------------------------------------------------------------- cookie

    private static void ApplyCookieDefaults(CookieAuthenticationOptions o, WebLoginDefinition definition)
    {
        o.Cookie.Name = CookieName;
        o.Cookie.HttpOnly = true;
        o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.Path = "/";
        o.Cookie.Domain = null;
        o.Cookie.IsEssential = true;
        o.ExpireTimeSpan = TimeSpan.FromHours(1);
        o.SlidingExpiration = true;
        // Sem ForwardChallenge: o TecCookieEvents decide antes do OIDC (que grava cookies de nonce e correlação já no início do
        // challenge) se é navegação (vai ao provedor) ou chamada de API (401 sem cookie nenhum)
        o.Events = new TecCookieEvents(definition);
    }

    internal static void EnforceCookie(CookieAuthenticationOptions o, string scheme)
    {
        if (!o.Cookie.HttpOnly || o.Cookie.SecurePolicy != CookieSecurePolicy.Always || o.Cookie.SameSite == SameSiteMode.None
            || o.Cookie.SameSite == SameSiteMode.Unspecified)
            throw new InvalidOperationException($"Esquema '{scheme}': o cookie de sessão deve ser HttpOnly, Secure e SameSite Lax ou Strict.");

        if (o.ExpireTimeSpan <= TimeSpan.Zero || o.ExpireTimeSpan > TimeSpan.FromHours(12))
            throw new InvalidOperationException($"Esquema '{scheme}': a sessão deve durar no máximo 12 horas (ExpireTimeSpan).");

        if (o.Cookie.Name?.StartsWith("__Host-", StringComparison.Ordinal) == true && (o.Cookie.Domain is not null || o.Cookie.Path != "/"))
            throw new InvalidOperationException($"Esquema '{scheme}': cookie '__Host-' exige Path=/ e nenhum Domain.");
    }

    /// <summary>
    /// A cada requisição: identidade normalizada, duração absoluta e tenant ainda ativo. A cada intervalo: normalização refeita
    /// (tenant e permissões atuais) e regra do provedor. Falha encerra a sessão (o próximo acesso pede login de novo).
    /// </summary>
    internal static async Task ValidateSessionAsync(CookieValidatePrincipalContext context, WebLoginDefinition definition)
    {
        var services = context.HttpContext.RequestServices;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.AspNetCore.WebLogin");
        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();
        var user = new SecurityUser(context.Principal);

        string? reason = null;
        if (!user.IsAuthenticated || user.Kind != TEC.Core.Security.PrincipalKind.User)
            reason = "sessão sem identidade normalizada";
        else if (ReadTime(context.Properties, SignedInAtKey) is not { } signedInAt || now - signedInAt >= definition.MaxSessionLifetime
                 || signedInAt > now.AddMinutes(5))
            reason = "duração máxima da sessão atingida";
        else if (user.TenantId is { } tenantId && services.GetRequiredService<ITenantRegistry>().Find(tenantId) is not { Enabled: true })
            reason = "tenant inativo ou removido";
        else if (user.TenantId is null && services.GetRequiredService<IOptionsMonitor<SecurityOptions>>().CurrentValue.RequireTenant)
            reason = "sessão sem tenant (RequireTenant)";

        if (reason is null && (ReadTime(context.Properties, ValidatedAtKey) is not { } validatedAt || now - validatedAt >= definition.RevalidationInterval))
        {
            if (definition.IsSessionAllowed?.Invoke(user, services) == false)
            {
                reason = "sessão recusada pela regra do provedor";
            }
            else
            {
                var refreshed = await services.GetRequiredService<SecurityIdentityFactory>()
                    .RevalidateAsync(context.Principal!, context.HttpContext.RequestAborted).ConfigureAwait(false);
                if (refreshed.IsSuccess)
                {
                    context.ReplacePrincipal(refreshed.Value);
                    context.Properties.Items[ValidatedAtKey] = now.ToString("O", CultureInfo.InvariantCulture);
                    context.ShouldRenew = true;
                }
                else
                {
                    reason = "revalidação recusada";
                }
            }
        }

        if (reason is not null)
        {
            AspNetCoreSecurityLog.SessionRejected(logger, definition.Scheme, reason);
            SecurityDiagnostics.RecordAuthenticationFailure(definition.Scheme, "session");
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(definition.Scheme).ConfigureAwait(false);
        }
    }

    private static DateTimeOffset? ReadTime(AuthenticationProperties properties, string key) =>
        properties.Items.TryGetValue(key, out string? value)
        && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var time)
            ? time
            : null;

    // ---------------------------------------------------------------- OpenID Connect

    private static void ApplyOidcDefaults(OpenIdConnectOptions o, WebLoginDefinition definition)
    {
        o.SignInScheme = definition.Scheme;
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.ResponseMode = OpenIdConnectResponseMode.FormPost;
        o.UsePkce = true;
        o.SaveTokens = false;
        o.GetClaimsFromUserInfoEndpoint = false;
        o.MapInboundClaims = false;
        o.RequireHttpsMetadata = true;
        o.UseTokenLifetime = false;
        o.DisableTelemetry = true;
        o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        o.CorrelationCookie.HttpOnly = true;
        o.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        o.NonceCookie.HttpOnly = true;
        o.ProtocolValidator.RequireNonce = true;
        o.ProtocolValidator.RequireState = true;
        o.Scope.Clear();
        o.Scope.Add(OpenIdConnectScope.OpenId);
        o.Scope.Add(OpenIdConnectScope.OpenIdProfile);
        o.Events = new TecOpenIdConnectEvents(definition);

        var parameters = o.TokenValidationParameters;
        parameters.ValidateIssuer = true;
        parameters.ValidateAudience = true;
        parameters.ValidateLifetime = true;
        parameters.ValidateIssuerSigningKey = true;
        parameters.RequireSignedTokens = true;
        parameters.RequireExpirationTime = true;
        parameters.ClockSkew = JwtHardening.DefaultClockSkew;
        parameters.ValidAlgorithms = [.. JwtHardening.DefaultAlgorithms];
        parameters.NameClaimType = TecClaimTypes.Name;
        parameters.RoleClaimType = TecClaimTypes.Role;
    }

    internal static void EnforceOidc(OpenIdConnectOptions o, string scheme)
    {
        void Require(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException($"Esquema '{scheme}': {message}");
        }

        var p = o.TokenValidationParameters;
        Require(o.ResponseType == OpenIdConnectResponseType.Code, "use somente o fluxo Authorization Code (ResponseType = code).");
        Require(o.UsePkce, "PKCE não pode ser desligado.");
        Require(o.RequireHttpsMetadata, "metadados devem ser obtidos por HTTPS.");
        Require(o.ProtocolValidator.RequireNonce && o.ProtocolValidator.RequireState, "nonce e state não podem ser desligados.");
        Require(p.ValidateIssuer && p.ValidateAudience && p.ValidateLifetime && p.ValidateIssuerSigningKey && p.RequireSignedTokens,
            "validação do ID token não pode ser desligada.");
        Require(p.SignatureValidator is null && p.LifetimeValidator is null, "validadores personalizados de assinatura/validade não são permitidos.");
        Require(p.AlgorithmValidator is null, "AlgorithmValidator personalizado não é permitido (use ValidAlgorithms).");
        Require(JwtHardening.AreAllowedAlgorithms(p.ValidAlgorithms, allowSymmetricKeys: false),
            "informe os algoritmos aceitos (ValidAlgorithms) só entre RS*, PS* e ES*: 'none' e HMAC não são permitidos.");
        Require(!o.SaveTokens && !o.MapInboundClaims, "SaveTokens e MapInboundClaims devem ficar desligados (tokens fora do cookie, claims originais).");
        Require(p.ClockSkew >= TimeSpan.Zero && p.ClockSkew <= JwtHardening.MaxClockSkew, "ClockSkew deve ficar entre 0 e 2 minutos.");
        Require(!string.IsNullOrWhiteSpace(o.ClientId), "ClientId é obrigatório.");
        Require(o.Authority is not null || o.Configuration is not null || o.MetadataAddress is not null, "Authority é obrigatório.");
    }

    /// <summary>Navegação de página (o navegador pede HTML). Chamadas de API recebem 401/403.</summary>
    internal static bool AcceptsHtml(HttpRequest request) =>
        request.Headers.Accept.Any(a => a?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true)
        && !string.Equals(request.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase);
}

/// <summary>Eventos do cookie do login web (métodos sobrescritos: trocar os delegates não pula a revalidação).</summary>
internal sealed class TecCookieEvents(WebLoginDefinition definition) : CookieAuthenticationEvents
{
    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        await base.ValidatePrincipal(context).ConfigureAwait(false);
        if (context.Principal is not null)
            await SecurityBuilderWebLoginExtensions.ValidateSessionAsync(context, definition).ConfigureAwait(false);
    }

    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
    {
        // Navegação de página: login no provedor (o OIDC usa a URL atual como retorno se RedirectUri estiver vazio)
        if (SecurityBuilderWebLoginExtensions.AcceptsHtml(context.Request))
            return context.HttpContext.ChallengeAsync(definition.ChallengeScheme, context.Properties);

        // Chamada de API (fetch/XHR): 401 sem passar pelo OIDC, para não acumular cookies de nonce/correlação a cada chamada
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return TecAuthorizationResultHandler.WriteBodyAsync(context.HttpContext);
    }
}

/// <summary>Eventos do OIDC do login web (métodos sobrescritos: trocar os delegates não pula a normalização).</summary>
internal sealed class TecOpenIdConnectEvents(WebLoginDefinition definition) : OpenIdConnectEvents
{
    public override async Task RedirectToIdentityProvider(RedirectContext context)
    {
        // Chamada de API (fetch/XHR, sem Accept: text/html): 401 em vez de redirecionar para a página de login
        if (!SecurityBuilderWebLoginExtensions.AcceptsHtml(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.HandleResponse();
            await TecAuthorizationResultHandler.WriteBodyAsync(context.HttpContext).ConfigureAwait(false);
            return;
        }

        await base.RedirectToIdentityProvider(context).ConfigureAwait(false);
    }

    public override async Task TokenValidated(TokenValidatedContext context)
    {
        await base.TokenValidated(context).ConfigureAwait(false);
        var services = context.HttpContext.RequestServices;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.AspNetCore.WebLogin");

        if (context.Result is not null)
        {
            // Um handler anterior concluiu sozinho: o principal não foi normalizado
            if (context.Result.Succeeded)
                Reject(context, logger, "evento OnTokenValidated anterior aprovou sem normalização");
            return;
        }

        ExternalIdentity? identity;
        string reason;
        try
        {
            identity = definition.CreateIdentity(context, out reason);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException)
        {
            identity = null;
            reason = "claim com formato inesperado (" + exception.GetType().Name + ")";
        }

        if (identity is null)
        {
            Reject(context, logger, reason);
            return;
        }

        var principal = await services.GetRequiredService<SecurityIdentityFactory>()
            .CreateAsync(identity, context.HttpContext.RequestAborted).ConfigureAwait(false);
        if (principal.IsFailure)
        {
            context.Fail("Login recusado.");
            return;
        }

        string now = services.GetRequiredService<TimeProvider>().GetUtcNow().ToString("O", CultureInfo.InvariantCulture);
        context.Principal = principal.Value;
        context.Properties!.Items[SecurityBuilderWebLoginExtensions.ValidatedAtKey] = now;
        context.Properties.Items[SecurityBuilderWebLoginExtensions.SignedInAtKey] = now;
    }

    public override async Task RemoteFailure(RemoteFailureContext context)
    {
        await base.RemoteFailure(context).ConfigureAwait(false);
        if (context.Result is not null)
            return;

        // Sem página de erro com detalhes do provedor: só o tipo no log e 401 genérico
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.AspNetCore.WebLogin");
        AspNetCoreSecurityLog.RemoteLoginRejected(logger, definition.ChallengeScheme, context.Failure?.GetType().Name ?? "desconhecido");
        SecurityDiagnostics.RecordAuthenticationFailure(definition.ChallengeScheme, "remote");
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.HandleResponse();
        await TecAuthorizationResultHandler.WriteBodyAsync(context.HttpContext).ConfigureAwait(false);
    }

    private void Reject(TokenValidatedContext context, ILogger logger, string reason)
    {
        AspNetCoreSecurityLog.RemoteLoginRejected(logger, definition.ChallengeScheme, reason);
        SecurityDiagnostics.RecordAuthenticationFailure(definition.ChallengeScheme, "identity");
        context.Fail("Login recusado.");
    }
}
