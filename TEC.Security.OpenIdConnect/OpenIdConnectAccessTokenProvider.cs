using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using TEC.Security.Abstractions;
using TEC.Security.Resilience;
using TEC.Security.Tokens;
using TEC.Vault.Abstractions;

namespace TEC.Security.OpenIdConnect;

/// <summary>
/// Provedor agnóstico de tokens de serviço M2M via OAuth 2.0 Client Credentials (RFC 6749) e Private Key JWT (RFC 7523).
/// Herda de <see cref="CachingAccessTokenProvider"/> garantindo cache resiliente, mitigação de concorrência e redação segura de erros.
/// </summary>
public sealed class OpenIdConnectAccessTokenProvider : CachingAccessTokenProvider
{
    private readonly HttpClient _httpClient;
    private readonly OpenIdConnectClientOptions _options;
    private readonly ISecretReader? _secretReader;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly string _tokenEndpoint;

    /// <summary>Cria o provedor de tokens M2M.</summary>
    public OpenIdConnectAccessTokenProvider(
        HttpClient httpClient,
        OpenIdConnectClientOptions options,
        ISecretReader? secretReader = null,
        TimeProvider? time = null,
        ILogger<OpenIdConnectAccessTokenProvider>? logger = null)
        : base(
            "OpenIdConnect.M2M",
            time,
            logger,
            options?.Resilience.Enabled == true
                ? SecurityCircuitBreaker.Create("OpenIdConnect.M2M", options.Resilience, timeProvider: time ?? TimeProvider.System, logger: logger)
                : null)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);

        if (options.AuthType == OpenIdConnectM2MAuthType.PrivateKeyJwt)
            throw new NotSupportedException("OpenIdConnectClientOptions: PrivateKeyJwt (RFC 7523) não é suportado sem provedor de chaves assimétricas/certificados; use AuthType = ClientSecret.");

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

        if (Uri.TryCreate(_tokenEndpoint, UriKind.Absolute, out var endpointUri))
        {
            if (endpointUri.Scheme != Uri.UriSchemeHttps && !endpointUri.IsLoopback)
                throw new InvalidOperationException($"TokenEndpoint '{_tokenEndpoint}' deve usar HTTPS (exceto loopback local).");
        }
        else
        {
            throw new InvalidOperationException($"TokenEndpoint '{_tokenEndpoint}' é inválido.");
        }

        if (!string.IsNullOrWhiteSpace(_options.Authority) &&
            Uri.TryCreate(_options.Authority, UriKind.Absolute, out var authUri))
        {
            if (authUri.Scheme != Uri.UriSchemeHttps && !authUri.IsLoopback)
                throw new InvalidOperationException($"Authority '{_options.Authority}' deve usar HTTPS (exceto loopback local).");
        }
    }

    /// <summary>Obtém um token de serviço para os escopos informados.</summary>
    public ValueTask<AccessToken> GetTokenAsync(IReadOnlyList<string> scopes) => GetTokenAsync(scopes, default);

    /// <inheritdoc />
    protected override async ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
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

        HttpResponseMessage response;
        try
        {
            response = await _httpClient.SendAsync(request, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new SecurityTokenAcquisitionException("Tempo limite ao contatar o endpoint de token do IdP.");
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                // Limita leitura de erro a no máximo 1024 bytes sem expor corpo sensível na mensagem da exceção
                byte[] buffer = new byte[1024];
                try
                {
                    using var errStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
                    _ = await errStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    // Ignora falhas na leitura do corpo de erro
                }

                throw new SecurityTokenAcquisitionException($"Falha ao obter token M2M do IdP. HTTP {(int)response.StatusCode}.");
            }

            var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                var root = doc.RootElement;

                if (!root.TryGetProperty("access_token", out var tokenProp) || tokenProp.GetString() is not { } tokenValue || string.IsNullOrEmpty(tokenValue))
                    throw new SecurityTokenAcquisitionException("Resposta do endpoint de token não contém 'access_token'.");

                int expiresIn = root.TryGetProperty("expires_in", out var expProp) && expProp.TryGetInt32(out int exp) ? exp : 3600;
                var expiresOn = _time.GetUtcNow().AddSeconds(expiresIn);

                return new AccessToken(tokenValue, expiresOn);
            }
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
}
