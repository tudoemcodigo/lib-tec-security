using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using TEC.Security.AspNetCore.Internal;
using TEC.Security.Claims;
using TEC.Security.Diagnostics;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Eventos dos esquemas bearer do TEC.Security. A normalização fica nos métodos sobrescritos, não nos delegates: código da
/// aplicação ou do provedor que troque <c>OnTokenValidated</c> roda <b>antes</b> e não consegue pular a normalização. Substituir
/// a instância inteira (<c>Events = new ...</c> ou <c>EventsType</c>) é recusado na validação das opções.
/// </summary>
/// <remarks>
/// Os delegates continuam rodando, mas não aprovam sozinhos (falha fechada): <c>Success()</c> ou um principal definido em
/// <c>OnMessageReceived</c> (antes da validação do token) ou em <c>OnAuthenticationFailed</c> (depois de o token ser recusado)
/// viram recusa, e um <c>OnTokenValidated</c> que aprove sozinho ou troque o token ou o principal validado também.
/// </remarks>
internal sealed class TecJwtBearerEvents(JwtProviderDefinition definition, SecurityAspNetCoreOptions options) : JwtBearerEvents
{
    public override async Task MessageReceived(MessageReceivedContext context)
    {
        await base.MessageReceived(context).ConfigureAwait(false);

        // OnMessageReceived só pode dizer onde está o token: aprovar aqui pularia a validação inteira
        if (context.Result?.Succeeded == true || context.Principal is not null)
        {
            Reject(context, Logger(context.HttpContext.RequestServices),
                "evento OnMessageReceived aprovou ou definiu a identidade antes da validação do token");
            return;
        }

        // WebSocket/SSE do SignalR: token na query string, somente nos hubs configurados
        if (context.Result is null && context.Token is null && context.Request.Headers.Authorization.Count == 0
            && TecSchemeSelector.TryGetHubToken(context.Request, options, out string hubToken))
            context.Token = hubToken;
    }

    public override async Task TokenValidated(TokenValidatedContext context)
    {
        // O que a validação produziu: um delegate que troque o token ou o principal não consegue normalizar outro conteúdo
        var validatedToken = context.SecurityToken;
        var validatedPrincipal = context.Principal;

        await base.TokenValidated(context).ConfigureAwait(false);
        var logger = Logger(context.HttpContext.RequestServices);

        if (context.Result is not null)
        {
            // Um handler anterior aprovou sozinho: o principal não foi normalizado (claims tec_* do provedor intactos)
            if (context.Result.Succeeded)
                Reject(context, logger, "evento OnTokenValidated anterior aprovou sem normalização");
            return;
        }

        if (!ReferenceEquals(context.SecurityToken, validatedToken) || !ReferenceEquals(context.Principal, validatedPrincipal))
        {
            Reject(context, logger, "evento OnTokenValidated trocou o token ou o principal validado");
            return;
        }

        if (context.SecurityToken is not JsonWebToken token)
        {
            Reject(context, logger, "tipo de token inesperado");
            return;
        }

        ExternalIdentity? identity;
        string reason;
        try
        {
            identity = definition.CreateIdentity(context, token, out reason);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException
                                              or System.Text.Json.JsonException)
        {
            identity = null;
            reason = "claim com formato inesperado (" + exception.GetType().Name + ")";
        }

        if (identity is null)
        {
            Reject(context, logger, reason);
            return;
        }

        var factory = context.HttpContext.RequestServices.GetRequiredService<SecurityIdentityFactory>();
        var principal = await factory.CreateAsync(identity, context.HttpContext.RequestAborted).ConfigureAwait(false);
        if (principal.IsFailure)
        {
            context.Fail("Identidade recusada.");
            return;
        }

        context.Principal = principal.Value;
        context.Success();
    }

    public override async Task AuthenticationFailed(AuthenticationFailedContext context)
    {
        await base.AuthenticationFailed(context).ConfigureAwait(false);
        var logger = Logger(context.HttpContext.RequestServices);

        // Só o tipo: a mensagem da exceção pode conter partes do token
        AspNetCoreSecurityLog.TokenRejected(logger, context.Scheme.Name, context.Exception.GetType().Name);
        SecurityDiagnostics.RecordAuthenticationFailure(context.Scheme.Name, "token");

        // Token recusado continua recusado: um delegate não transforma a falha em aprovação
        if (context.Result?.Succeeded == true || context.Principal is not null)
        {
            AspNetCoreSecurityLog.TokenRejected(logger, context.Scheme.Name, "evento OnAuthenticationFailed aprovou um token recusado");
            context.Fail(context.Exception);
        }
    }

    // Uma instância de eventos por esquema (opções em cache): o logger é criado uma vez, sem consulta ao container por token
    private ILogger? _logger;

    private ILogger Logger(IServiceProvider services) =>
        _logger ??= services.GetRequiredService<ILoggerFactory>().CreateLogger("TEC.Security.AspNetCore.JwtBearer");

    private static void Reject(ResultContext<JwtBearerOptions> context, ILogger logger, string reason)
    {
        AspNetCoreSecurityLog.TokenRejected(logger, context.Scheme.Name, reason);
        SecurityDiagnostics.RecordAuthenticationFailure(context.Scheme.Name, "identity");
        context.Fail("Token recusado.");
    }
}
