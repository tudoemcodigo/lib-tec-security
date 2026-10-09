using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using TEC.Core.Security;
using TEC.Core.Threading;
using TEC.Security.Claims;
using TEC.Security.Diagnostics;
using TEC.Security.EntraId.Internal;
using TEC.Security.Tokens;

namespace TEC.Security.EntraId;

/// <summary>
/// <see cref="DelegatingHandler"/> que troca o token do usuário da requisição atual (recebido por uma API Entra ID) por um token
/// para o serviço de destino (On-Behalf-Of), mantendo a identidade do usuário na cadeia de chamadas.
/// </summary>
/// <remarks>
/// <para>Falha fechada (<see cref="HttpRequestException"/>): destino fora de <see cref="AccessTokenHandlerOptions.AllowedHosts"/> ou
/// sem HTTPS; requisição sem usuário autenticado por um esquema Entra ID (tokens de aplicação não têm OBO); tenant do usuário
/// (<c>tid</c>) ausente ou fora do formato GUID. A política de tenants já foi aplicada antes, pelo esquema de autenticação da
/// API que validou o token recebido.</para>
/// <para>Cache por usuário (hash do token recebido) + escopos, até 5 minutos antes da expiração; o token recebido nunca vai
/// para log ou chave de cache em claro. Uma troca por usuário + escopos em andamento
/// (<see cref="TEC.Core.Threading.SingleFlight{TKey, TValue}"/>): requisições simultâneas aguardam a mesma.</para>
/// </remarks>
internal sealed class EntraIdOnBehalfOfHandler(
    IHttpContextAccessor accessor,
    EntraIdClientCredential credential,
    EntraIdTokenEndpoint endpoint,
    EntraIdCloud cloud,
    string clientId,
    AccessTokenHandlerOptions options,
    IMemoryCache cache,
    SingleFlight<string, Abstractions.AccessToken> flights,
    TimeProvider time,
    ILogger<EntraIdOnBehalfOfHandler> logger) : DelegatingHandler
{
    private readonly string[] _scopes = [.. options.Scopes];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Headers.Authorization is null)
        {
            if (!options.IsAllowedDestination(request.RequestUri))
                throw new HttpRequestException("Destino não autorizado a receber o token On-Behalf-Of (AllowedHosts/HTTPS).");

            var token = await GetTokenAsync(cancellationToken).ConfigureAwait(false);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        var context = accessor.HttpContext ?? throw new HttpRequestException("On-Behalf-Of exige uma requisição HTTP com usuário.");
        var user = new SecurityUser(context.User);

        if (user.Kind != PrincipalKind.User || user.Provider != EntraIdTenantPolicy.ProviderName || user.ExternalTenantId is not { } tenantId
            || !EntraIdCloud.IsGuid(tenantId) || !TryGetBearer(context.Request, out string userToken))
            throw new HttpRequestException("On-Behalf-Of exige usuário autenticado por token Entra ID (tokens de aplicação não são aceitos).");

        string key = CacheKey(userToken);
        if (cache.TryGetValue(key, out Abstractions.AccessToken? cached) && cached is not null
            && cached.ExpiresOn - time.GetUtcNow() > CachingAccessTokenProvider.RefreshBefore)
            return cached.Token;

        // Uma troca por usuário + escopos: requisições simultâneas do mesmo usuário aguardam a mesma (sem rajada no Entra ID)
        var exchanged = await flights.RunAsync(key, (k, ct) => ExchangeAsync(k, user, tenantId, userToken, ct), cancellationToken)
            .ConfigureAwait(false);
        return exchanged.Token;
    }

    private async Task<Abstractions.AccessToken> ExchangeAsync(string key, SecurityUser user, string tenantId, string userToken,
        CancellationToken cancellationToken)
    {
        long start = System.Diagnostics.Stopwatch.GetTimestamp();
        using var activity = SecurityDiagnostics.StartTokenAcquisition("EntraId.OnBehalfOf");
        try
        {
            string tokenEndpoint = cloud.TokenEndpoint(tenantId);
            // Autenticação da aplicação a cada tentativa (assertion nova, com jti próprio, em cada retentativa)
            var token = await endpoint.OnBehalfOfAsync(tokenEndpoint, clientId,
                ct => credential.GetClientAuthenticationAsync(tokenEndpoint, ct), userToken, _scopes, cancellationToken).ConfigureAwait(false);

            var lifetime = token.ExpiresOn - time.GetUtcNow() - CachingAccessTokenProvider.RefreshBefore;
            if (lifetime > TimeSpan.Zero)
                cache.Set(key, token, new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = lifetime, Size = 1 });

            SecurityDiagnostics.RecordTokenAcquisition("EntraId.OnBehalfOf", cacheHit: false,
                System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalSeconds, null);
            return token;
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            string errorType = exception.GetType().Name;
            activity?.SetStatus(System.Diagnostics.ActivityStatusCode.Error);
            SecurityDiagnostics.RecordTokenAcquisition("EntraId.OnBehalfOf", cacheHit: false,
                System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalSeconds, errorType);
            EntraIdLog.OnBehalfOfFailed(logger, exception, user.Id ?? "?", errorType);
            throw new SecurityTokenAcquisitionException(exception);
        }
    }

    private string CacheKey(string userToken)
    {
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(Encoding.UTF8.GetBytes(userToken), hash);
        return "tec-obo\n" + Convert.ToHexString(hash) + "\n" + string.Join(' ', _scopes.Order(StringComparer.Ordinal));
    }

    private static bool TryGetBearer(HttpRequest request, out string token)
    {
        token = string.Empty;
        var header = request.Headers.Authorization;
        if (header.Count != 1 || header[0] is not { } value || !value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return false;

        token = value[7..].Trim();
        return token.Length > 0;
    }
}
