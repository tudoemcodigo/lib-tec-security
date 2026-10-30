using System.Globalization;
using System.Security.Claims;
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
    /// chamadas de API (sem <c>Accept: text/html</c>). Uso pelos pacotes de provedor (ex.: <c>AddOpenIdConnectWebLogin</c>).
    /// </summary>
    /// <remarks>
    /// <para>O cookie é protegido pelo Data Protection do ASP.NET Core: com mais de uma instância, persista as chaves em local
    /// compartilhado e protegido (ex.: <c>PersistKeysToAzureBlobStorage</c> + <c>ProtectKeysWithAzureKeyVault</c>). Só a
    /// identidade normalizada entra no cookie, e só ela é reconstruída na leitura; não troque o <c>TicketDataFormat</c> por um
    /// formato sem essa proteção.</para>
    /// <para>Os delegates de evento do OIDC e do cookie continuam rodando, mas não aprovam sozinhos: <c>Success()</c> ou um
    /// principal trocado antes da normalização (<c>OnMessageReceived</c>, <c>OnAuthorizationCodeReceived</c>,
    /// <c>OnTokenResponseReceived</c>, <c>OnAuthenticationFailed</c>, <c>OnTokenValidated</c>) ou depois dela
    /// (<c>OnTicketReceived</c>) recusam o login, e gravar no cookie uma identidade que não veio do
    /// <see cref="SecurityIdentityFactory"/> lança <see cref="InvalidOperationException"/>.</para>
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
    /// (tenant e permissões atuais) e regra do provedor. Falha encerra a sessão (o próximo acesso pede login de novo), exceto
    /// falha passageira do <c>IPermissionStore</c> (<see cref="Common.SecurityErrors.ProviderFailureCode"/>): só a requisição
    /// atual fica sem identidade, a sessão é mantida e a revalidação é tentada de novo na próxima requisição.
    /// </summary>
    internal static async Task ValidateSessionAsync(CookieValidatePrincipalContext context, WebLoginDefinition definition)
    {
        var services = context.HttpContext.RequestServices;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.AspNetCore.WebLogin");
        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();
        var user = new SecurityUser(context.Principal);

        string? reason = null;
        bool keepSession = false;
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
                else if (refreshed.Error?.Code == Common.SecurityErrors.ProviderFailureCode)
                {
                    // Falha passageira do store de permissões: nega esta requisição sem permissões velhas, mas não desloga
                    reason = "revalidação indisponível (falha do provedor de permissões); sessão mantida";
                    keepSession = true;
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
            if (!keepSession)
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
        Require(o.RequireHttpsMetadata || (o.Authority is not null && Uri.TryCreate(o.Authority, UriKind.Absolute, out var aUri) && aUri.IsLoopback),
            "metadados devem ser obtidos por HTTPS (exceto loopback local).");
        Require(o.ProtocolValidator.RequireNonce && o.ProtocolValidator.RequireState, "nonce e state não podem ser desligados.");
        Require(p.ValidateIssuer && p.ValidateAudience && p.ValidateLifetime && p.ValidateIssuerSigningKey && p.RequireSignedTokens,
            "validação do ID token não pode ser desligada.");
        Require(p.SignatureValidator is null && p.SignatureValidatorUsingConfiguration is null, "SignatureValidator personalizado não é permitido.");
        Require(p.LifetimeValidator is null, "LifetimeValidator personalizado não é permitido.");
        Require(p.AlgorithmValidator is null, "AlgorithmValidator personalizado não é permitido (use ValidAlgorithms).");
        Require(p.IssuerSigningKeyResolver is null && p.IssuerSigningKeyResolverUsingConfiguration is null, "IssuerSigningKeyResolver personalizado não é permitido.");
        Require(p.IssuerSigningKeyValidator is null && p.IssuerSigningKeyValidatorUsingConfiguration is null, "IssuerSigningKeyValidator personalizado não é permitido.");
        Require(p.IssuerValidator is null && p.IssuerValidatorUsingConfiguration is null, "IssuerValidator personalizado não é permitido.");
        Require(p.AudienceValidator is null, "AudienceValidator personalizado não é permitido.");
        Require(p.TokenReader is null, "TokenReader personalizado não é permitido.");
        Require(p.TokenDecryptionKeyResolver is null && p.TokenDecryptionKey is null && p.TokenDecryptionKeys?.Any() != true, "tokens cifrados não são permitidos.");
        Require(p.TransformBeforeSignatureValidation is null, "TransformBeforeSignatureValidation não é permitido.");
        Require(p.CryptoProviderFactory is null, "CryptoProviderFactory personalizada não é permitida.");
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
        // O cookie é cifrado e autenticado pelo Data Protection e só recebe identidade normalizada (SigningIn): a identidade lida
        // dele é reconstruída antes do delegate da aplicação, e o que o delegate puser no lugar só passa se também for normalizado
        if (context.Principal is not null && NormalizedIdentity.RestoreTrusted(context.Principal) is { } restored
            && !ReferenceEquals(restored, context.Principal))
            context.ReplacePrincipal(restored);

        await base.ValidatePrincipal(context).ConfigureAwait(false);
        if (context.Principal is not null)
            await SecurityBuilderWebLoginExtensions.ValidateSessionAsync(context, definition).ConfigureAwait(false);
    }

    public override async Task SigningIn(CookieSigningInContext context)
    {
        await base.SigningIn(context).ConfigureAwait(false);

        // A leitura do cookie confia no conteúdo (RestoreTrusted): por isso só a identidade criada pelo SecurityIdentityFactory
        // pode ser gravada nele, venha a chamada do OIDC, de um delegate ou de um SignInAsync da aplicação
        var user = new SecurityUser(context.Principal);
        if (!user.IsAuthenticated || user.Kind != TEC.Core.Security.PrincipalKind.User)
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.AspNetCore.WebLogin");
            AspNetCoreSecurityLog.RemoteLoginRejected(logger, definition.Scheme, "identidade sem normalização ao gravar o cookie de sessão");
            SecurityDiagnostics.RecordAuthenticationFailure(definition.Scheme, "session");
            throw new InvalidOperationException(
                $"Esquema '{definition.Scheme}': o cookie de sessão só aceita a identidade de usuário criada pelo TEC.Security (SecurityIdentityFactory).");
        }
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

/// <summary>
/// Eventos do OIDC do login web (métodos sobrescritos: trocar os delegates não pula a normalização). Os delegates rodam antes e
/// não aprovam sozinhos: <c>Success()</c> ou principal trocado antes da normalização recusam o login (falha fechada).
/// </summary>
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

    // Antes do ID token ser validado, nenhum evento pode aprovar o login nem definir a identidade

    public override async Task MessageReceived(MessageReceivedContext context)
    {
        var principal = context.Principal;
        await base.MessageReceived(context).ConfigureAwait(false);
        RejectEarlyApproval(context, principal, "OnMessageReceived");
    }

    public override async Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
    {
        var principal = context.Principal;
        await base.AuthorizationCodeReceived(context).ConfigureAwait(false);
        RejectEarlyApproval(context, principal, "OnAuthorizationCodeReceived");
    }

    public override async Task TokenResponseReceived(TokenResponseReceivedContext context)
    {
        var principal = context.Principal;
        await base.TokenResponseReceived(context).ConfigureAwait(false);
        RejectEarlyApproval(context, principal, "OnTokenResponseReceived");
    }

    public override async Task AuthenticationFailed(AuthenticationFailedContext context)
    {
        var principal = context.Principal;
        await base.AuthenticationFailed(context).ConfigureAwait(false);
        RejectEarlyApproval(context, principal, "OnAuthenticationFailed");
    }

    public override async Task TokenValidated(TokenValidatedContext context)
    {
        // O que a validação produziu: um delegate que troque o token, o principal ou o nonce não consegue normalizar outro conteúdo
        var validatedToken = context.SecurityToken;
        var validatedPrincipal = context.Principal;
        string? validatedNonce = context.Nonce;

        await base.TokenValidated(context).ConfigureAwait(false);
        var services = context.HttpContext.RequestServices;
        var logger = Logger(context.HttpContext);

        if (context.Result is not null)
        {
            // Um handler anterior concluiu sozinho: o principal não foi normalizado
            if (context.Result.Succeeded)
                Reject(context, logger, "evento OnTokenValidated anterior aprovou sem normalização");
            return;
        }

        if (!ReferenceEquals(context.SecurityToken, validatedToken) || !ReferenceEquals(context.Principal, validatedPrincipal)
            || !string.Equals(context.Nonce, validatedNonce, StringComparison.Ordinal))
        {
            Reject(context, logger, "evento OnTokenValidated trocou o token, o principal ou o nonce validados");
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

    public override async Task TicketReceived(TicketReceivedContext context)
    {
        // Principal normalizado no TokenValidated: entre ele e o cookie, nenhum delegate pode trocá-lo
        var normalized = context.Principal;
        await base.TicketReceived(context).ConfigureAwait(false);

        // O delegate respondeu ou pulou: não há SignIn
        if (context.Result is { Handled: true } or { Skipped: true })
            return;

        if (ReferenceEquals(context.Principal, normalized) && SecurityUser.FindNormalizedIdentity(context.Principal) is not null)
            return;

        AspNetCoreSecurityLog.RemoteLoginRejected(Logger(context.HttpContext), definition.ChallengeScheme,
            "evento OnTicketReceived trocou a identidade normalizada");
        SecurityDiagnostics.RecordAuthenticationFailure(definition.ChallengeScheme, "identity");
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.HandleResponse();
        await TecAuthorizationResultHandler.WriteBodyAsync(context.HttpContext).ConfigureAwait(false);
    }

    public override async Task RemoteFailure(RemoteFailureContext context)
    {
        await base.RemoteFailure(context).ConfigureAwait(false);
        if (context.Result is not null)
            return;

        // Sem página de erro com detalhes do provedor: só o tipo no log e 401 genérico
        AspNetCoreSecurityLog.RemoteLoginRejected(Logger(context.HttpContext), definition.ChallengeScheme,
            context.Failure?.GetType().Name ?? "desconhecido");
        SecurityDiagnostics.RecordAuthenticationFailure(definition.ChallengeScheme, "remote");
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.HandleResponse();
        await TecAuthorizationResultHandler.WriteBodyAsync(context.HttpContext).ConfigureAwait(false);
    }

    /// <summary>Recusa o login se o delegate aprovou (<c>Success()</c>) ou trocou o principal antes da normalização.</summary>
    private void RejectEarlyApproval(RemoteAuthenticationContext<OpenIdConnectOptions> context, ClaimsPrincipal? principal, string eventName)
    {
        if (context.Result?.Succeeded != true && ReferenceEquals(context.Principal, principal))
            return;

        AspNetCoreSecurityLog.RemoteLoginRejected(Logger(context.HttpContext), definition.ChallengeScheme,
            "evento " + eventName + " aprovou ou definiu a identidade antes da normalização");
        SecurityDiagnostics.RecordAuthenticationFailure(definition.ChallengeScheme, "identity");
        context.Fail("Login recusado.");
    }

    private void Reject(TokenValidatedContext context, ILogger logger, string reason)
    {
        AspNetCoreSecurityLog.RemoteLoginRejected(logger, definition.ChallengeScheme, reason);
        SecurityDiagnostics.RecordAuthenticationFailure(definition.ChallengeScheme, "identity");
        context.Fail("Login recusado.");
    }

    private static ILogger Logger(HttpContext context) =>
        context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.AspNetCore.WebLogin");
}
