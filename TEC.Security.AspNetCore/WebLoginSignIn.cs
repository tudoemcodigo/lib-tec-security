using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using TEC.Core.Common.Results;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.AspNetCore.Internal;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Diagnostics;

namespace TEC.Security.AspNetCore;

/// <summary>
/// Abre a sessão do login web a partir de um ID token que o servidor obteve direto do endpoint de token do IdP (login por senha num
/// BFF confidencial, ADR SEC 0002 da Doutrina). É a mesma identidade do fluxo de código: o token é validado com o handler, as
/// chaves, o emissor e a audiência do esquema OIDC, a identidade nasce no <see cref="SecurityIdentityFactory"/> e o cookie tem as
/// mesmas regras de revalidação e duração.
/// </summary>
/// <remarks>
/// <para>Não há <c>nonce</c>: o token não passou pelo navegador, veio do canal de servidor com autenticação do cliente. Quem chama
/// garante que o ID token veio desse canal, e nunca de entrada do usuário.</para>
/// <para>Falha esperada (token inválido, identidade recusada) volta como <see cref="Result"/> com o motivo só no log, sem
/// detalhe ao chamador; o cookie não é gravado.</para>
/// </remarks>
public sealed class WebLoginSignIn
{
    private readonly WebLoginDefinition _definition;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidc;
    private readonly SecurityIdentityFactory _factory;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    internal WebLoginSignIn(WebLoginDefinition definition, IOptionsMonitor<OpenIdConnectOptions> oidc, SecurityIdentityFactory factory,
        TimeProvider time, ILoggerFactory loggers)
    {
        _definition = definition;
        _oidc = oidc;
        _factory = factory;
        _time = time;
        _logger = loggers.CreateLogger("TEC.Security.AspNetCore.WebLogin");
    }

    /// <summary>Esquema do cookie da sessão.</summary>
    public string Scheme => _definition.Scheme;

    /// <summary>Se o provedor do login web aceita esta entrada (<see cref="WebLoginDefinition.CreateIdentityFromClaims"/>).</summary>
    public bool Supported => _definition.CreateIdentityFromClaims is not null;

    /// <summary>
    /// Valida o ID token, normaliza a identidade e grava o cookie com <paramref name="properties"/> (onde quem chama já pôs o que
    /// é seu, como o identificador da sessão do BFF).
    /// </summary>
    /// <returns>Sucesso, ou falha <c>NAO_AUTENTICADO</c> sem detalhe.</returns>
    public async Task<Result> SignInWithIdTokenAsync(HttpContext context, string idToken, AuthenticationProperties properties,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(properties);
        if (_definition.CreateIdentityFromClaims is not { } createIdentity)
            return Reject("o provedor do login web não aceita ID token fora do fluxo de código");
        if (string.IsNullOrEmpty(idToken) || idToken.Length > 16 * 1024)
            return Reject("ID token ausente ou grande demais");

        var oidc = _oidc.Get(_definition.ChallengeScheme);
        var configuration = oidc.Configuration
                            ?? await (oidc.ConfigurationManager ?? throw new InvalidOperationException("Login web sem metadados do provedor."))
                                .GetConfigurationAsync(cancellationToken).ConfigureAwait(false);

        // Os mesmos parâmetros endurecidos do esquema; emissor, chaves e audiência vêm dos metadados, como no handler do OIDC
        var parameters = oidc.TokenValidationParameters.Clone();
        if (string.IsNullOrEmpty(parameters.ValidIssuer) && (parameters.ValidIssuers is null || !parameters.ValidIssuers.Any()))
            parameters.ValidIssuer = configuration.Issuer;
        parameters.IssuerSigningKeys = (parameters.IssuerSigningKeys ?? []).Concat(configuration.SigningKeys).ToList();
        if (string.IsNullOrEmpty(parameters.ValidAudience) && (parameters.ValidAudiences is null || !parameters.ValidAudiences.Any()))
            parameters.ValidAudience = oidc.ClientId;

        TokenValidationResult validation;
        try
        {
            validation = await oidc.TokenHandler.ValidateTokenAsync(idToken, parameters).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException or SecurityTokenException)
        {
            return Reject("ID token inválido (" + exception.GetType().Name + ")");
        }

        if (!validation.IsValid || validation.ClaimsIdentity is null)
            return Reject("ID token inválido (" + (validation.Exception?.GetType().Name ?? "sem identidade") + ")");

        ExternalIdentity? identity;
        string reason;
        try
        {
            identity = createIdentity([.. validation.ClaimsIdentity.Claims], context.RequestServices, out reason);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException)
        {
            identity = null;
            reason = "claim com formato inesperado (" + exception.GetType().Name + ")";
        }

        if (identity is null)
            return Reject(reason);

        var principal = await _factory.CreateAsync(identity, cancellationToken).ConfigureAwait(false);
        if (principal.IsFailure)
            return Reject("identidade recusada pelo normalizador");

        string now = _time.GetUtcNow().ToString("O", CultureInfo.InvariantCulture);
        properties.Items[SecurityBuilderWebLoginExtensions.ValidatedAtKey] = now;
        properties.Items[SecurityBuilderWebLoginExtensions.SignedInAtKey] = now;
        await context.SignInAsync(_definition.Scheme, principal.Value, properties).ConfigureAwait(false);
        return Result.Success();
    }

    private Result Reject(string reason)
    {
        AspNetCoreSecurityLog.RemoteLoginRejected(_logger, _definition.Scheme, reason);
        SecurityDiagnostics.RecordAuthenticationFailure(_definition.Scheme, "direct_sign_in");
        return Result.Failure(SecurityErrors.Unauthenticated());
    }
}
