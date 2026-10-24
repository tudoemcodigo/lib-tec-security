using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore.Internal;
using TEC.Security.Claims;
using TEC.Security.Diagnostics;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Autenticação por API key (header configurado em <c>Security:ApiKeys:HeaderName</c>): identidade de aplicação com o tenant,
/// papéis e permissões do cadastro.
/// </summary>
/// <remarks>
/// Recusa (HTTP 401): mais de um header, chave inválida/expirada/desativada, tenant inativo e, com
/// <see cref="SecurityAspNetCoreOptions.ApiKeyRequiresHttps"/>, requisição sem HTTPS. A chave nunca é lida da query string.
/// </remarks>
internal sealed class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ApiKeyValidator validator,
    SecurityIdentityFactory factory,
    SecurityAspNetCoreOptions securityOptions,
    IHostEnvironment? environment = null)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var values = Request.Headers[validator.HeaderName];
        if (values.Count == 0)
            return AuthenticateResult.NoResult();

        if (values.Count != 1)
            return Reject("mais de um header de API key");

        if (securityOptions.ApiKeyRequiresHttps && !Request.IsHttps && environment?.IsDevelopment() != true)
            return Reject("API key recebida sem HTTPS");

        var identity = validator.Validate(values[0], Scheme.Name);
        if (identity is null)
            return AuthenticateResult.Fail("API key inválida.");

        var principal = await factory.CreateAsync(identity, Context.RequestAborted).ConfigureAwait(false);
        return principal.IsSuccess
            ? AuthenticateResult.Success(new AuthenticationTicket(principal.Value, Scheme.Name))
            : AuthenticateResult.Fail("Identidade recusada.");
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }

    private AuthenticateResult Reject(string reason)
    {
        AspNetCoreSecurityLog.CredentialRejected(Logger, reason);
        SecurityDiagnostics.RecordAuthenticationFailure(Scheme.Name, "api_key");
        return AuthenticateResult.Fail("API key inválida.");
    }
}
