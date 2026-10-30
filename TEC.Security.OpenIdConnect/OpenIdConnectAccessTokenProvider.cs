using System.Buffers;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TEC.Security.Abstractions;
using TEC.Security.Resilience;
using TEC.Security.Tokens;
using TEC.Vault.Abstractions;

namespace TEC.Security.OpenIdConnect;

/// <summary>
/// Provedor agnóstico de tokens de serviço M2M via OAuth 2.0 Client Credentials (RFC 6749), autenticado por client secret.
/// Herda de <see cref="CachingAccessTokenProvider"/> garantindo cache resiliente, mitigação de concorrência e redação segura de erros.
/// </summary>
/// <remarks>
/// <para>As opções são conferidas na criação (as mesmas regras do <c>ValidateOnStart</c> do <c>AddOpenIdConnectClient</c>).</para>
/// <para>Resposta do endpoint de token, sempre com falha fechada (<see cref="SecurityTokenAcquisitionException"/>): o
/// <see cref="OpenIdConnectClientOptions.Timeout"/> vale do envio até a leitura completa do corpo; status fora de 2xx (inclusive
/// 3xx) é falha, sem ler o corpo; o corpo tem teto de 256 KB; sem <c>access_token</c> é falha; <c>expires_in</c> presente
/// precisa ser um inteiro positivo (número ou texto numérico) e, ausente, vale uma validade conservadora de 60 segundos;
/// acima de 24 horas, o cache considera 24 horas.</para>
/// <para>Com um <see cref="HttpClient"/> próprio, desligue o seguimento de redirecionamentos no handler (o
/// <c>AddOpenIdConnectClient</c> já faz isso): o client secret vai no corpo do POST.</para>
/// </remarks>
public sealed class OpenIdConnectAccessTokenProvider : CachingAccessTokenProvider
{
    /// <summary>Teto do corpo da resposta do endpoint de token.</summary>
    internal const int MaxResponseBytes = 256 * 1024;

    /// <summary>Validade assumida quando a resposta não traz <c>expires_in</c>: curta, para o token ser renovado logo.</summary>
    internal static readonly TimeSpan LifetimeWithoutExpiresIn = TimeSpan.FromSeconds(60);

    /// <summary>Validade máxima considerada no cache, mesmo que o <c>expires_in</c> seja maior.</summary>
    internal static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(24);

    /// <summary>Maior <see cref="OpenIdConnectClientOptions.Timeout"/> aceito.</summary>
    internal static readonly TimeSpan MaxTimeout = TimeSpan.FromMinutes(5);

    private readonly HttpClient _httpClient;
    private readonly OpenIdConnectClientOptions _options;
    private readonly ISecretReader? _secretReader;
    private readonly TimeProvider _time;
    private readonly string _tokenEndpoint;

    /// <summary>Cria o provedor de tokens M2M.</summary>
    /// <exception cref="NotSupportedException"><see cref="OpenIdConnectM2MAuthType.PrivateKeyJwt"/>.</exception>
    /// <exception cref="InvalidOperationException">Opções inválidas ou inseguras, ou <c>ClientSecretName</c> sem <paramref name="secretReader"/>.</exception>
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

        ValidateOptions(options);
        if (string.IsNullOrEmpty(options.ClientSecret) && secretReader is null)
            throw new InvalidOperationException("OpenIdConnectClientOptions: ClientSecretName informado, mas nenhum ISecretReader foi injetado.");

        _httpClient = httpClient;
        _options = options;
        _secretReader = secretReader;
        _time = time ?? TimeProvider.System;
        _tokenEndpoint = ResolveTokenEndpoint(options);
    }

    /// <summary>Obtém um token de serviço para os escopos informados.</summary>
    public ValueTask<AccessToken> GetTokenAsync(IReadOnlyList<string> scopes) => GetTokenAsync(scopes, default);

    /// <summary>Confere as opções (as mesmas regras do construtor e do <c>ValidateOnStart</c>).</summary>
    /// <exception cref="NotSupportedException"><see cref="OpenIdConnectM2MAuthType.PrivateKeyJwt"/>.</exception>
    /// <exception cref="InvalidOperationException">Opção ausente, fora do limite ou insegura.</exception>
    internal static void ValidateOptions(OpenIdConnectClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.AuthType == OpenIdConnectM2MAuthType.PrivateKeyJwt)
            throw new NotSupportedException("OpenIdConnectClientOptions: PrivateKeyJwt (RFC 7523) não é suportado; use AuthType = ClientSecret.");
        if (options.AuthType != OpenIdConnectM2MAuthType.ClientSecret)
            throw new InvalidOperationException("OpenIdConnectClientOptions: AuthType inválido.");

        if (string.IsNullOrWhiteSpace(options.ClientId))
            throw new InvalidOperationException("OpenIdConnectClientOptions: informe o ClientId.");

        if (string.IsNullOrWhiteSpace(options.TokenEndpoint) && string.IsNullOrWhiteSpace(options.Authority))
            throw new InvalidOperationException("OpenIdConnectClientOptions: informe TokenEndpoint ou Authority.");

        string endpoint = ResolveTokenEndpoint(options);
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var endpointUri))
            throw new InvalidOperationException($"TokenEndpoint '{endpoint}' é inválido.");
        if (endpointUri.Scheme != Uri.UriSchemeHttps && !endpointUri.IsLoopback)
            throw new InvalidOperationException($"TokenEndpoint '{endpoint}' deve usar HTTPS (exceto loopback local).");

        if (!string.IsNullOrWhiteSpace(options.Authority) && Uri.TryCreate(options.Authority, UriKind.Absolute, out var authUri)
            && authUri.Scheme != Uri.UriSchemeHttps && !authUri.IsLoopback)
            throw new InvalidOperationException($"Authority '{options.Authority}' deve usar HTTPS (exceto loopback local).");

        if (options.Timeout <= TimeSpan.Zero || options.Timeout > MaxTimeout)
            throw new InvalidOperationException("OpenIdConnectClientOptions: Timeout deve ser maior que zero e de no máximo 5 minutos.");

        if (string.IsNullOrEmpty(options.ClientSecret) && string.IsNullOrEmpty(options.ClientSecretName))
            throw new InvalidOperationException("OpenIdConnectClientOptions: informe ClientSecret ou ClientSecretName para autenticação M2M.");

        options.Resilience.Validate("OpenIdConnectClientOptions.Resilience");
    }

    /// <inheritdoc />
    protected override async ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
    {
        string secret = await ResolveClientSecretAsync(cancellationToken).ConfigureAwait(false);

        var parameters = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = _options.ClientId,
            ["client_secret"] = secret
        };

        if (scopes.Count > 0)
        {
            parameters["scope"] = string.Join(' ', scopes);
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint)
        {
            Content = new FormUrlEncodedContent(parameters)
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // O tempo limite vale até a leitura completa do corpo: um IdP que responde os headers e trava no corpo também é cortado
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(_options.Timeout);

        try
        {
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);

            // O corpo de erro não é lido (pode trazer detalhes do IdP); 3xx também é falha (redirecionamento não é seguido)
            if (!response.IsSuccessStatusCode)
                throw new SecurityTokenAcquisitionException($"Falha ao obter token M2M do IdP. HTTP {(int)response.StatusCode}.");

            return await ReadTokenAsync(response.Content, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new SecurityTokenAcquisitionException("Tempo limite ao contatar o endpoint de token do IdP.");
        }
    }

    private async Task<AccessToken> ReadTokenAsync(HttpContent content, CancellationToken cancellationToken)
    {
        if (content.Headers.ContentLength is > MaxResponseBytes)
            throw new SecurityTokenAcquisitionException("Resposta do endpoint de token acima do tamanho máximo.");

        // Um byte além do teto denuncia a resposta grande demais, mesmo sem Content-Length (chunked)
        byte[] buffer = ArrayPool<byte>.Shared.Rent(MaxResponseBytes + 1);
        try
        {
            int total = 0;
            var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                int read;
                while ((read = await stream.ReadAsync(buffer.AsMemory(total, MaxResponseBytes + 1 - total), cancellationToken).ConfigureAwait(false)) > 0)
                {
                    total += read;
                    if (total > MaxResponseBytes)
                        throw new SecurityTokenAcquisitionException("Resposta do endpoint de token acima do tamanho máximo.");
                }
            }

            // O BOM UTF-8 é aceito, como na leitura por stream
            var json = buffer.AsMemory(0, total);
            if (json.Span.StartsWith("﻿"u8))
                json = json[3..];

            return ParseToken(json);
        }
        finally
        {
            // O buffer teve o token: limpo antes de voltar ao pool
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    private AccessToken ParseToken(ReadOnlyMemory<byte> json)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            throw new SecurityTokenAcquisitionException("Resposta do endpoint de token não é um JSON válido.");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("access_token", out var tokenProp)
                || tokenProp.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(tokenProp.GetString()))
                throw new SecurityTokenAcquisitionException("Resposta do endpoint de token não contém 'access_token'.");

            return new AccessToken(tokenProp.GetString()!, _time.GetUtcNow().Add(ReadLifetime(root)));
        }
    }

    /// <summary>
    /// Validade do token: <c>expires_in</c> inteiro e positivo (número ou texto numérico, como no endpoint v1 do Entra ID),
    /// limitado a <see cref="MaxLifetime"/>; ausente, <see cref="LifetimeWithoutExpiresIn"/>; qualquer outro valor, falha.
    /// </summary>
    private static TimeSpan ReadLifetime(JsonElement root)
    {
        if (!root.TryGetProperty("expires_in", out var expiresIn) || expiresIn.ValueKind == JsonValueKind.Null)
            return LifetimeWithoutExpiresIn;

        long seconds = 0;
        bool parsed = expiresIn.ValueKind switch
        {
            JsonValueKind.Number => expiresIn.TryGetInt64(out seconds),
            JsonValueKind.String => long.TryParse(expiresIn.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out seconds),
            _ => false
        };

        if (!parsed || seconds <= 0)
            throw new SecurityTokenAcquisitionException("Resposta do endpoint de token com 'expires_in' inválido.");

        return seconds >= (long)MaxLifetime.TotalSeconds ? MaxLifetime : TimeSpan.FromSeconds(seconds);
    }

    private static string ResolveTokenEndpoint(OpenIdConnectClientOptions options) =>
        !string.IsNullOrWhiteSpace(options.TokenEndpoint)
            ? options.TokenEndpoint
            : options.Authority.TrimEnd('/') + "/protocol/openid-connect/token";

    private async Task<string> ResolveClientSecretAsync(CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(_options.ClientSecret))
            return _options.ClientSecret;

        // O construtor garante ClientSecretName e o leitor; o segredo é lido a cada obtenção (acompanha a rotação no cofre)
        var secretResult = await _secretReader!.GetSecretAsync(_options.ClientSecretName!, cancellationToken: cancellationToken).ConfigureAwait(false);
        if (!secretResult.IsSuccess || secretResult.Value is null || string.IsNullOrEmpty(secretResult.Value.Value))
            throw new InvalidOperationException($"Segredo '{_options.ClientSecretName}' não encontrado no cofre TEC.Vault.");

        return secretResult.Value.Value;
    }
}
