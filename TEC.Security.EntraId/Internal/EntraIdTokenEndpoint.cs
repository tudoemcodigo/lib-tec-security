using System.Globalization;
using System.Net.Http.Headers;
using System.Text.Json;

namespace TEC.Security.EntraId.Internal;

/// <summary>
/// Chamada ao endpoint de token do Entra ID para o On-Behalf-Of (grant <c>jwt-bearer</c>). O corpo da resposta de erro nunca
/// é registrado nem repassado: só o código <c>error</c> (validado como identificador curto).
/// </summary>
/// <remarks>
/// A resposta é lida com teto de <see cref="MaxResponseBytes"/> mesmo sem <c>Content-Length</c> (resposta em partes): um
/// endpoint adulterado ou um proxy defeituoso não consegue esgotar a memória do processo.
/// </remarks>
internal sealed class EntraIdTokenEndpoint(HttpClient http, TimeProvider time)
{
    public const string HttpClientName = "TEC.Security.EntraId.TokenEndpoint";

    internal const int MaxResponseBytes = 64 * 1024;

    /// <summary>Validade máxima aceita para o token devolvido (o Entra ID emite tokens de 60 a 90 minutos).</summary>
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromHours(24);

    public async Task<Abstractions.AccessToken> OnBehalfOfAsync(string tokenEndpoint, string clientId, ClientAuthentication client,
        string userAssertion, IReadOnlyList<string> scopes, CancellationToken cancellationToken)
    {
        var form = new List<KeyValuePair<string, string>>
        {
            new("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            new("client_id", clientId),
            new("assertion", userAssertion),
            new("requested_token_use", "on_behalf_of"),
            new("scope", string.Join(' ', scopes))
        };

        if (client.Secret is not null)
            form.Add(new("client_secret", client.Secret));
        else
        {
            form.Add(new("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
            form.Add(new("client_assertion", client.Assertion!));
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint) { Content = new FormUrlEncodedContent(form) };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        if (response.Content.Headers.ContentLength > MaxResponseBytes)
            throw new HttpRequestException("Resposta do endpoint de token grande demais.");

        byte[] body = await ReadBoundedAsync(response.Content, cancellationToken).ConfigureAwait(false);
        return Parse(body, response.IsSuccessStatusCode, (int)response.StatusCode, time.GetUtcNow());
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

    /// <summary>Código de erro OAuth (ex.: <c>invalid_grant</c>) ou marcador fixo, para não levar texto arbitrário ao log.</summary>
    internal static string SafeCode(string? code) =>
        code is { Length: > 0 and <= 64 } && code.All(c => char.IsAsciiLetterOrDigit(c) || c == '_') ? code : "codigo-invalido";
}
