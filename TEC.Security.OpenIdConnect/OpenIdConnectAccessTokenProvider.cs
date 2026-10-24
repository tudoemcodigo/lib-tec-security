using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Security.Abstractions;
using TEC.Security.Diagnostics;
using TEC.Security.Resilience;
using TEC.Security.Tokens;
using TEC.Vault.Abstractions;

namespace TEC.Security.OpenIdConnect;

/// <summary>
/// Provedor agnóstico de tokens de serviço M2M via OAuth 2.0 Client Credentials (RFC 6749) e Private Key JWT (RFC 7523).
/// </summary>
public sealed class OpenIdConnectAccessTokenProvider : IAccessTokenProvider, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly OpenIdConnectClientOptions _options;
    private readonly ISecretReader? _secretReader;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
    private readonly SecurityCircuitBreaker? _circuitBreaker;
    private readonly string _tokenEndpoint;

    /// <summary>Cria o provedor de tokens M2M.</summary>
    public OpenIdConnectAccessTokenProvider(
        HttpClient httpClient,
        OpenIdConnectClientOptions options,
        ISecretReader? secretReader = null,
        TimeProvider? time = null,
        ILogger<OpenIdConnectAccessTokenProvider>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.ClientId))
            throw new InvalidOperationException("OpenIdConnectClientOptions: informe o ClientId.");

        if (string.IsNullOrWhiteSpace(options.TokenEndpoint) && string.IsNullOrWhiteSpace(options.Authority))
            throw new InvalidOperationException("OpenIdConnectClientOptions: informe TokenEndpoint ou Authority.");

        _httpClient = httpClient;
        _options = options;
        _secretReader = secretReader;
        _time = time ?? TimeProvider.System;
        _logger = logger ?? (ILogger)NullLogger.Instance;

        _tokenEndpoint = !string.IsNullOrWhiteSpace(_options.TokenEndpoint)
            ? _options.TokenEndpoint
            : _options.Authority.TrimEnd('/') + "/protocol/openid-connect/token";

        if (_options.Resilience.Enabled)
            _circuitBreaker = SecurityCircuitBreaker.Create("OpenIdConnect.M2M", _options.Resilience, timeProvider: _time, logger: _logger);
    }

    /// <inheritdoc />
    public async ValueTask<AccessToken> GetTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken = default)
    {
        var scopeList = (scopes ?? []).OrderBy(s => s, StringComparer.Ordinal).ToList();
        string cacheKey = "tec-m2m-token:" + _options.ClientId + ":" + string.Join(' ', scopeList);

        var entry = _cache.GetOrAdd(cacheKey, static _ => new CacheEntry());

        var now = _time.GetUtcNow();
        if (entry.Cached is { } current && now < entry.RefreshAt)
        {
            SecurityDiagnostics.RecordTokenAcquisition("OpenIdConnect.M2M", cacheHit: true, 0, null);
            return current;
        }

        await entry.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            now = _time.GetUtcNow();
            if (entry.Cached is { } fresh && now < entry.RefreshAt)
            {
                SecurityDiagnostics.RecordTokenAcquisition("OpenIdConnect.M2M", cacheHit: true, 0, null);
                return fresh;
            }

            var acquired = _circuitBreaker is not null
                ? await _circuitBreaker.ExecuteAsync(ct => AcquireTokenCoreAsync(scopeList, ct), cancellationToken).ConfigureAwait(false)
                : await AcquireTokenCoreAsync(scopeList, cancellationToken).ConfigureAwait(false);

            now = _time.GetUtcNow();
            var refreshMargin = CachingAccessTokenProvider.RefreshMargin(acquired.ExpiresOn - now);
            var refreshAt = acquired.ExpiresOn - refreshMargin;

            entry.Cached = acquired;
            entry.RefreshAt = refreshAt > now ? refreshAt : acquired.ExpiresOn;

            return acquired;
        }
        finally
        {
            entry.Lock.Release();
        }
    }

    private async ValueTask<AccessToken> AcquireTokenCoreAsync(List<string> scopes, CancellationToken cancellationToken)
    {
        var start = System.Diagnostics.Stopwatch.GetTimestamp();

        try
        {
            string secret = await ResolveClientSecretAsync(cancellationToken).ConfigureAwait(false);

            var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = _options.ClientId
            };

            if (_options.AuthType == OpenIdConnectM2MAuthType.ClientSecret)
            {
                parameters["client_secret"] = secret;
            }

            if (scopes.Count > 0)
            {
                parameters["scope"] = string.Join(' ', scopes);
            }

            using var request = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint)
            {
                Content = new FormUrlEncodedContent(parameters)
            };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(_options.Timeout);

            using var response = await _httpClient.SendAsync(request, cts.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                string errorBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException($"Falha ao obter token M2M de '{_tokenEndpoint}'. HTTP {(int)response.StatusCode}: {errorBody}");
            }

            var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                var root = doc.RootElement;

                if (!root.TryGetProperty("access_token", out var tokenProp) || tokenProp.GetString() is not { } tokenValue || string.IsNullOrEmpty(tokenValue))
                    throw new InvalidOperationException("Resposta do endpoint de token não contém 'access_token'.");

                int expiresIn = root.TryGetProperty("expires_in", out var expProp) && expProp.TryGetInt32(out int exp) ? exp : 3600;
                var expiresOn = _time.GetUtcNow().AddSeconds(expiresIn);

                SecurityDiagnostics.RecordTokenAcquisition("OpenIdConnect.M2M", cacheHit: false, System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalSeconds, null);

                return new AccessToken(tokenValue, expiresOn);
            }
        }
        catch (Exception ex)
        {
            SecurityDiagnostics.RecordTokenAcquisition("OpenIdConnect.M2M", cacheHit: false, System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalSeconds, ex.GetType().Name);
            throw;
        }
    }

    private async Task<string> ResolveClientSecretAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_options.ClientSecret))
            return _options.ClientSecret;

        if (!string.IsNullOrEmpty(_options.ClientSecretName))
        {
            if (_secretReader is null)
                throw new InvalidOperationException("OpenIdConnectClientOptions: ClientSecretName informado, mas ISecretReader não foi injetado.");

            var secretResult = await _secretReader.GetSecretAsync(_options.ClientSecretName, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (!secretResult.IsSuccess || secretResult.Value is null || string.IsNullOrEmpty(secretResult.Value.Value))
                throw new InvalidOperationException($"Segredo '{_options.ClientSecretName}' não encontrado no cofre TEC.Vault.");

            return secretResult.Value.Value;
        }

        throw new InvalidOperationException("OpenIdConnectClientOptions: informe ClientSecret ou ClientSecretName para autenticação M2M.");
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var entry in _cache.Values)
            entry.Lock.Dispose();
        _cache.Clear();
    }

    private sealed class CacheEntry
    {
        public SemaphoreSlim Lock { get; } = new(1, 1);
        public AccessToken? Cached { get; set; }
        public DateTimeOffset RefreshAt { get; set; }
    }
}
