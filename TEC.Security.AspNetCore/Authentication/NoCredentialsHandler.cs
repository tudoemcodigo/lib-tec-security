using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Security.AspNetCore.Internal;
using TEC.Security.Diagnostics;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Esquema das requisições sem credencial reconhecida: sem credencial nenhuma é anônimo (<see cref="AuthenticateResult.NoResult"/>);
/// com uma credencial que nenhum provedor aceita (outro tipo de header <c>Authorization</c>, emissor não registrado, token
/// malformado ou acima do tamanho máximo) a autenticação <b>falha</b>, em vez de seguir como anônima.
/// </summary>
internal sealed class NoCredentialsHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    SecuritySchemes schemes,
    SecurityAspNetCoreOptions securityOptions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        bool hasCredential = Request.Headers.Authorization.Count > 0
                             || TecSchemeSelector.TryGetHubToken(Request, securityOptions, out _);

        if (!hasCredential)
            return Task.FromResult(AuthenticateResult.NoResult());

        AspNetCoreSecurityLog.CredentialRejected(Logger, "credencial não reconhecida por nenhum provedor registrado");
        SecurityDiagnostics.RecordAuthenticationFailure(Scheme.Name, "token");
        return Task.FromResult(AuthenticateResult.Fail("Credencial não reconhecida."));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        if (schemes.Bearer.Count > 0)
            Response.Headers.WWWAuthenticate = "Bearer";
        return Task.CompletedTask;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}
