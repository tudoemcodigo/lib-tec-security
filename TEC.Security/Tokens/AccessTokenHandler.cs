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
    /// Destino autorizado a receber o token: host em <see cref="AllowedHosts"/>, sem usuário na URL e com HTTPS (ou HTTP em
    /// loopback com <see cref="AllowHttpForLoopback"/>).
    /// </summary>
    /// <param name="uri">Destino da requisição.</param>
    /// <returns><c>true</c> se o token pode ser anexado.</returns>
    public bool IsAllowedDestination(Uri? uri) =>
        TryGetDestinationHost(uri, AllowHttpForLoopback, out string? host) && AllowedHosts.Contains(host, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Regra única de destino (usada também pelos handlers, que conferem o host num conjunto já montado): URL absoluta, sem
    /// usuário, com HTTPS (ou HTTP em loopback quando permitido). Devolve o host (IDN) a conferir na lista.
    /// </summary>
    /// <param name="uri">Destino da requisição.</param>
    /// <param name="allowHttpForLoopback">Aceita HTTP para loopback.</param>
    /// <param name="host">Host (IDN) a conferir em <see cref="AllowedHosts"/>.</param>
    /// <returns><c>false</c> se o destino é recusado independentemente do host.</returns>
    internal static bool TryGetDestinationHost(Uri? uri, bool allowHttpForLoopback, [NotNullWhen(true)] out string? host)
    {
        host = null;
        if (uri is null || !uri.IsAbsoluteUri || !string.IsNullOrEmpty(uri.UserInfo))
            return false;

        if (uri.Scheme != Uri.UriSchemeHttps && !(allowHttpForLoopback && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
            return false;

        host = uri.IdnHost;
        return true;
    }

    /// <summary>Confere escopos e hosts.</summary>
    /// <exception cref="InvalidOperationException">Sem escopo ou sem host permitido.</exception>
    public void Validate()
    {
        if (Scopes.Count == 0 || Scopes.Any(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException("AccessTokenHandler: informe ao menos um escopo (ex.: api://<client-id>/.default).");

        if (AllowedHosts.Count == 0 || AllowedHosts.Any(h => string.IsNullOrWhiteSpace(h) || Uri.CheckHostName(h) == UriHostNameType.Unknown))
            throw new InvalidOperationException("AccessTokenHandler: informe AllowedHosts com os hosts de destino (ex.: api.contoso.com).");
    }
}

/// <summary>
/// <see cref="DelegatingHandler"/> que anexa <c>Authorization: Bearer</c> com o token de serviço do
/// <see cref="IAccessTokenProvider"/>, somente para os hosts permitidos e com HTTPS.
/// </summary>
/// <remarks>
/// <para>Registrado pelos pacotes de provedor (ex.: <c>AddEntraIdAccessToken</c> no <c>IHttpClientBuilder</c>).</para>
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

    internal bool IsAllowed(Uri? uri) =>
        AccessTokenHandlerOptions.TryGetDestinationHost(uri, _allowHttpForLoopback, out string? host) && _hosts.Contains(host);
}
