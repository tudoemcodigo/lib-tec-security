using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using TEC.Security.Abstractions;
using TEC.Security.Internal;

namespace TEC.Security.Tokens;

/// <summary>Opções do <see cref="AccessTokenHandler"/>.</summary>
public sealed class AccessTokenHandlerOptions
{
    /// <summary>Escopos pedidos (ex.: <c>api://&lt;client-id-da-api&gt;/.default</c>). Obrigatório.</summary>
    public List<string> Scopes { get; } = [];

    /// <summary>
    /// Hosts que podem receber o token (comparação exata, sem diferenciar maiúsculas; ex.: <c>api.contoso.com</c>). Obrigatório.
    /// </summary>
    /// <remarks>
    /// O token dá acesso ao serviço de destino em nome da aplicação. Se uma URL vier de dado externo (redirecionamento, campo
    /// de configuração adulterado, SSRF), o token não pode ir para outro host. Requisições para hosts fora da lista, ou sem
    /// HTTPS, são <b>bloqueadas</b> com <see cref="HttpRequestException"/>.
    /// </remarks>
    public List<string> AllowedHosts { get; } = [];

    /// <summary>
    /// Permite HTTP sem TLS para <c>localhost</c>/loopback (desenvolvimento com serviços locais). Padrão: <c>false</c>.
    /// </summary>
    public bool AllowHttpForLoopback { get; set; }

    /// <summary>
    /// Destino autorizado a receber o token: host (ou host:porta) em <see cref="AllowedHosts"/>, sem usuário na URL e com HTTPS (ou HTTP em
    /// loopback com <see cref="AllowHttpForLoopback"/>). Entradas sem porta exigem a porta padrão do protocolo (443 para HTTPS, 80 para HTTP).
    /// </summary>
    /// <param name="uri">Destino da requisição.</param>
    /// <returns><c>true</c> se o token pode ser anexado.</returns>
    public bool IsAllowedDestination(Uri? uri) =>
        TryGetDestinationTarget(uri, AllowHttpForLoopback, out string? hostWithoutPort, out string? hostWithPort)
        && (AllowedHosts.Contains(hostWithPort, StringComparer.OrdinalIgnoreCase)
            || (uri!.IsDefaultPort && AllowedHosts.Contains(hostWithoutPort, StringComparer.OrdinalIgnoreCase)));

    /// <summary>
    /// Regra única de destino: URL absoluta, sem usuário, com HTTPS (ou HTTP em loopback quando permitido). Devolve tanto o host
    /// puro quanto host:porta a conferir na lista.
    /// </summary>
    internal static bool TryGetDestinationTarget(Uri? uri, bool allowHttpForLoopback,
        [NotNullWhen(true)] out string? hostWithoutPort, [NotNullWhen(true)] out string? hostWithPort)
    {
        hostWithoutPort = null;
        hostWithPort = null;
        if (uri is null || !uri.IsAbsoluteUri || !string.IsNullOrEmpty(uri.UserInfo))
            return false;

        if (uri.Scheme != Uri.UriSchemeHttps && !(allowHttpForLoopback && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
            return false;

        hostWithoutPort = uri.IdnHost;
        hostWithPort = $"{uri.IdnHost}:{uri.Port}";
        return true;
    }

    /// <summary>
    /// Regra única de destino (compatibilidade): devolve o host (IDN) a conferir na lista.
    /// </summary>
    /// <param name="uri">Destino da requisição.</param>
    /// <param name="allowHttpForLoopback">Aceita HTTP para loopback.</param>
    /// <param name="host">Host (IDN) a conferir em <see cref="AllowedHosts"/>.</param>
    /// <returns><c>false</c> se o destino é recusado independentemente do host.</returns>
    internal static bool TryGetDestinationHost(Uri? uri, bool allowHttpForLoopback, [NotNullWhen(true)] out string? host)
    {
        bool allowed = TryGetDestinationTarget(uri, allowHttpForLoopback, out host, out _);
        return allowed;
    }

    /// <summary>Confere escopos e hosts.</summary>
    /// <exception cref="InvalidOperationException">Sem escopo ou sem host permitido.</exception>
    public void Validate()
    {
        if (Scopes.Count == 0 || Scopes.Any(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException("AccessTokenHandler: informe ao menos um escopo (ex.: api://<client-id>/.default).");

        if (AllowedHosts.Count == 0 || AllowedHosts.Any(h => !IsValidAllowedHostEntry(h)))
            throw new InvalidOperationException("AccessTokenHandler: informe AllowedHosts com os hosts de destino válidos (ex.: api.contoso.com ou api.contoso.com:8443).");
    }

    internal static bool IsValidAllowedHostEntry(string? entry)
    {
        if (string.IsNullOrWhiteSpace(entry))
            return false;

        string host = entry;
        int colon = entry.IndexOf(':');
        if (colon >= 0)
        {
            host = entry[..colon];
            string portText = entry[(colon + 1)..];
            if (!int.TryParse(portText, System.Globalization.CultureInfo.InvariantCulture, out int port) || port <= 0 || port > 65535)
                return false;
        }

        return Uri.CheckHostName(host) != UriHostNameType.Unknown;
    }
}

/// <summary>
/// <see cref="DelegatingHandler"/> que anexa <c>Authorization: Bearer</c> com o token de serviço do
/// <see cref="IAccessTokenProvider"/>, somente para os hosts permitidos e com HTTPS.
/// </summary>
/// <remarks>
/// <para>Registrado pelos pacotes de provedor (ex.: <c>AddOpenIdConnectAccessToken</c> no <c>IHttpClientBuilder</c>).</para>
/// <para>Um header <c>Authorization</c> já presente na requisição é mantido (o handler não sobrescreve).</para>
/// <para>Redirecionamentos: o <see cref="HttpClientHandler"/> remove o header <c>Authorization</c> ao seguir um redirect, então
/// o token não acompanha um 302 para outro domínio.</para>
/// </remarks>
public sealed class AccessTokenHandler : DelegatingHandler
{
    private readonly IAccessTokenProvider _provider;
    private readonly string[] _scopes;
    private readonly FrozenSet<string> _hosts;
    private readonly bool _allowHttpForLoopback;
    private readonly ILogger? _logger;

    /// <summary>Cria o handler. As opções são validadas aqui.</summary>
    public AccessTokenHandler(IAccessTokenProvider provider, AccessTokenHandlerOptions options, ILogger<AccessTokenHandler>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        _provider = provider;
        _scopes = [.. options.Scopes];
        _hosts = options.AllowedHosts.ToFrozenSet(StringComparer.OrdinalIgnoreCase);
        _allowHttpForLoopback = options.AllowHttpForLoopback;
        _logger = logger;
    }

    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Headers.Authorization is null)
        {
            var uri = request.RequestUri;
            if (!IsAllowed(uri))
            {
                string host = uri is { IsAbsoluteUri: true } ? uri.IdnHost : "(relativo)";
                if (_logger is not null)
                    SecurityLog.TokenNotAttached(_logger, host);
                throw new HttpRequestException("Destino não autorizado a receber o token de serviço (AllowedHosts/HTTPS).");
            }

            var token = await _provider.GetTokenAsync(_scopes, cancellationToken).ConfigureAwait(false);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    internal bool IsAllowed(Uri? uri)
    {
        if (!AccessTokenHandlerOptions.TryGetDestinationTarget(uri, _allowHttpForLoopback, out string? hostWithoutPort, out string? hostWithPort))
            return false;

        return _hosts.Contains(hostWithPort) || (uri!.IsDefaultPort && _hosts.Contains(hostWithoutPort));
    }
}
