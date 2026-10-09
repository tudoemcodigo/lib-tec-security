using System.Globalization;
using System.Net.Http.Headers;
using System.Net;
using System.Text.Json;
using Polly;
using Polly.Retry;
using TEC.Security.Resilience;

namespace TEC.Security.EntraId.Internal;

/// <summary>
/// Chamada ao endpoint de token do Entra ID para o On-Behalf-Of (grant <c>jwt-bearer</c>). O corpo da resposta de erro nunca
/// é registrado nem repassado: só o código <c>error</c> (validado como identificador curto).
/// </summary>
/// <remarks>
/// A resposta é lida com teto de <see cref="MaxResponseBytes"/> mesmo sem <c>Content-Length</c> (resposta em partes): um
/// endpoint adulterado ou um proxy defeituoso não consegue esgotar a memória do processo.
/// <para>Falha de rede, tempo limite, HTTP 408, 429 e 5xx são repetidos (<see cref="EntraIdResilienceOptions"/>); erros OAuth
/// nunca. O circuit breaker, se houver, fica por fora das retentativas e só conta essas falhas transitórias.</para>
/// </remarks>
internal sealed class EntraIdTokenEndpoint
{
    private readonly HttpClient _http;
    private readonly TimeProvider _time;
    private readonly ResiliencePipeline _retry;
    private readonly SecurityCircuitBreaker? _circuitBreaker;

    public EntraIdTokenEndpoint(HttpClient http, TimeProvider time, EntraIdResilienceOptions? resilience = null,
        SecurityCircuitBreaker? circuitBreaker = null)
    {
        _http = http;
        _time = time;
        _circuitBreaker = circuitBreaker;
        _retry = CreateRetry(resilience ?? new EntraIdResilienceOptions { MaxRetries = 0 }, time);
    }

    public const string HttpClientName = "TEC.Security.EntraId.TokenEndpoint";

    internal const int MaxResponseBytes = 64 * 1024;

    /// <summary>Validade máxima aceita para o token devolvido (o Entra ID emite tokens de 60 a 90 minutos).</summary>
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(24);

    public Task<Abstractions.AccessToken> OnBehalfOfAsync(string tokenEndpoint, string clientId, ClientAuthentication client,
        string userAssertion, IReadOnlyList<string> scopes, CancellationToken cancellationToken) =>
        OnBehalfOfAsync(tokenEndpoint, clientId, _ => Task.FromResult(client), userAssertion, scopes, cancellationToken);

    /// <summary>
    /// Troca On-Behalf-Of. A autenticação da aplicação é obtida <b>a cada tentativa</b>: uma client assertion assinada (com
    /// <c>jti</c> próprio) nunca é reenviada, então uma retentativa não é recusada como repetição.
    /// </summary>
    public async Task<Abstractions.AccessToken> OnBehalfOfAsync(string tokenEndpoint, string clientId,
        Func<CancellationToken, Task<ClientAuthentication>> clientAuthentication, string userAssertion, IReadOnlyList<string> scopes,
        CancellationToken cancellationToken)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            new("client_id", clientId),
            new("assertion", userAssertion),
            new("requested_token_use", "on_behalf_of"),
            new("scope", string.Join(' ', scopes))
        };

        var state = (Endpoint: this, Url: tokenEndpoint, Form: form, Client: clientAuthentication);
        if (_circuitBreaker is null)
            return await SendWithRetryAsync(state, cancellationToken).ConfigureAwait(false);

        return await _circuitBreaker.ExecuteAsync(ct => SendWithRetryAsync(state, ct), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Falhas que contam para o circuit breaker do On-Behalf-Of: só as transitórias (as que seriam repetidas).</summary>
    internal static bool IsTransient(Exception exception) => exception is TransientTokenEndpointException;

    private ValueTask<Abstractions.AccessToken> SendWithRetryAsync(
        (EntraIdTokenEndpoint Endpoint, string Url, List<KeyValuePair<string, string>> Form, Func<CancellationToken, Task<ClientAuthentication>> Client) state,
        CancellationToken cancellationToken) =>
        _retry.ExecuteAsync(static (s, ct) => s.Endpoint.SendOnceAsync(s.Url, s.Form, s.Client, ct), state, cancellationToken);

    private async ValueTask<Abstractions.AccessToken> SendOnceAsync(string tokenEndpoint, List<KeyValuePair<string, string>> baseForm,
        Func<CancellationToken, Task<ClientAuthentication>> clientAuthentication, CancellationToken cancellationToken)
    {
        var client = await clientAuthentication(cancellationToken).ConfigureAwait(false);
        var form = new List<KeyValuePair<string, string>>(baseForm);
        if (client.Secret is not null)
            form.Add(new("client_secret", client.Secret));
        else
        {
            form.Add(new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            form.Add(new("client_assertion", client.Assertion!));
        }

        // Uma requisição por tentativa (HttpRequestMessage não pode ser reenviada)
        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = new FormUrlEncodedContent(form) };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            throw new TransientTokenEndpointException("Falha de rede ao chamar o endpoint de token.", null, null, exception);
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            // Tempo limite do HttpClient (não é cancelamento do chamador)
            throw new TransientTokenEndpointException("Tempo limite ao chamar o endpoint de token.", null, null, exception);
        }

        using (response)
        {
            int status = (int)response.StatusCode;
            if (status is 408 or 429 or >= 500)
            {
                throw new TransientTokenEndpointException($"Endpoint de token indisponível (HTTP {status}).", response.StatusCode,
                    RetryAfter(response, _time.GetUtcNow()));
            }

            if (response.Content.Headers.ContentLength > MaxResponseBytes)
                throw new HttpRequestException("Resposta do endpoint de token grande demais.");

            byte[] body = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
            return Parse(body, response.IsSuccessStatusCode, status, _time.GetUtcNow());
        }
    }

    private static ResiliencePipeline CreateRetry(EntraIdResilienceOptions options, TimeProvider time)
    {
        var builder = new ResiliencePipelineBuilder { TimeProvider = time };
        if (options.MaxRetries == 0)
            return builder.Build();

        var maxDelay = options.MaxRetryDelay;
        return builder.AddRetry(new RetryStrategyOptions
        {
            MaxRetryAttempts = options.MaxRetries,
            BackoffType = DelayBackoffType.Exponential,
            UseJitter = true,
            Delay = maxDelay < TimeSpan.FromMilliseconds(500) ? maxDelay : TimeSpan.FromMilliseconds(500),
            MaxDelay = maxDelay > TimeSpan.Zero ? maxDelay : null,
            // Retry-After acima do limite: desiste na hora em vez de segurar a requisição do usuário
            ShouldHandle = args => ValueTask.FromResult(args.Outcome.Exception is TransientTokenEndpointException failure
                && (failure.RetryAfter is null || failure.RetryAfter <= maxDelay)),
            DelayGenerator = static args => ValueTask.FromResult(
                args.Outcome.Exception is TransientTokenEndpointException { RetryAfter: { } retryAfter } ? (TimeSpan?)retryAfter : null)
        }).Build();
    }

    /// <summary>Espera pedida em <c>Retry-After</c> (segundos ou data), ou <c>null</c>.</summary>
    internal static TimeSpan? RetryAfter(HttpResponseMessage response, DateTimeOffset now)
    {
        var header = response.Headers.RetryAfter;
        if (header?.Delta is { } delta)
            return delta < TimeSpan.Zero ? TimeSpan.Zero : delta;
        if (header?.Date is { } date)
            return date <= now ? TimeSpan.Zero : date - now;
        return null;
    }

    /// <summary>Interpreta a resposta do endpoint de token (separado da rede para os testes).</summary>
    internal static Abstractions.AccessToken Parse(ReadOnlyMemory<byte> body, bool success, int statusCode, DateTimeOffset now)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            throw new HttpRequestException($"Resposta do endpoint de token não é JSON válido (HTTP {statusCode}).");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new HttpRequestException($"Resposta do endpoint de token fora do formato (HTTP {statusCode}).");

            if (!success)
            {
                string code = root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.String
                    ? SafeCode(error.GetString())
                    : "desconhecido";
                throw new HttpRequestException($"On-Behalf-Of recusado pelo Entra ID: {code} (HTTP {statusCode}).");
            }

            if (!root.TryGetProperty("access_token", out var token) || token.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(token.GetString()) || !root.TryGetProperty("expires_in", out var expiresIn))
                throw new HttpRequestException("Resposta do endpoint de token sem access_token/expires_in.");

            long seconds = expiresIn.ValueKind switch
            {
                JsonValueKind.Number when expiresIn.TryGetInt64(out long number) => number,
                JsonValueKind.String when long.TryParse(expiresIn.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) => parsed,
                _ => 0
            };
            if (seconds <= 0 || seconds > MaxLifetime.TotalSeconds)
                throw new HttpRequestException("Resposta do endpoint de token com expires_in inválido.");

            return new Abstractions.AccessToken(token.GetString()!, now.AddSeconds(seconds));
        }
    }

    /// <summary>Lê o corpo inteiro, com teto de <see cref="MaxResponseBytes"/>.</summary>
    internal static async Task<byte[]> ReadBoundedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            using var buffer = new MemoryStream();
            byte[] chunk = new byte[8 * 1024];
            int read;
            while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > MaxResponseBytes)
                    throw new HttpRequestException("Resposta do endpoint de token grande demais.");
                buffer.Write(chunk, 0, read);
            }

            return buffer.ToArray();
        }
    }

    /// <summary>Falha transitória do endpoint de token (rede, tempo limite, 408, 429, 5xx): repetida e contada pelo circuit breaker.</summary>
    internal sealed class TransientTokenEndpointException(string message, HttpStatusCode? statusCode, TimeSpan? retryAfter,
        Exception? innerException = null) : HttpRequestException(message, innerException, statusCode)
    {
        public TimeSpan? RetryAfter { get; } = retryAfter;
    }

    /// <summary>Código de erro OAuth (ex.: <c>invalid_grant</c>) ou marcador fixo, para não levar texto arbitrário ao log.</summary>
    internal static string SafeCode(string? code) =>
        code is { Length: > 0 and <= 64 } && code.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') ? code : "codigo-invalido";
}
