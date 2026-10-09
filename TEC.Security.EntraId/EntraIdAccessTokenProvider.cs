using Azure.Core;
using Microsoft.Extensions.Logging;
using TEC.Security.EntraId.Internal;
using TEC.Security.Tokens;
using AccessToken = TEC.Security.Abstractions.AccessToken;

namespace TEC.Security.EntraId;

/// <summary>
/// Tokens da própria aplicação (client credentials) no Entra ID, com cache e renovação antecipada. Registrado por
/// <c>AddEntraIdClient</c> como <see cref="Abstractions.IAccessTokenProvider"/>.
/// </summary>
public sealed class EntraIdAccessTokenProvider : CachingAccessTokenProvider
{
    private readonly TokenCredential _credential;

    internal EntraIdAccessTokenProvider(EntraIdClientCredential credential, TimeProvider? time, ILogger<EntraIdAccessTokenProvider>? logger,
        TEC.Security.Resilience.SecurityCircuitBreaker? circuitBreaker = null)
        : base(EntraIdTenantPolicy.ProviderName, time, logger, circuitBreaker)
    {
        _credential = credential.CreateTokenCredential();
    }

    /// <inheritdoc />
    protected override async ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
    {
        var token = await _credential.GetTokenAsync(new TokenRequestContext([.. scopes]), cancellationToken).ConfigureAwait(false);
        return new AccessToken(token.Token, token.ExpiresOn);
    }
}
