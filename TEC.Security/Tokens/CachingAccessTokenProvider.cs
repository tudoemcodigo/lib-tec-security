using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using TEC.Core.Common.Results;
using TEC.Core.Exceptions;
using TEC.Security.Abstractions;
using TEC.Security.Common;
using TEC.Security.Diagnostics;
using TEC.Security.Internal;
using TEC.Security.Resilience;

namespace TEC.Security.Tokens;

/// <summary>
/// Base para provedores de token de serviço: cache por conjunto de escopos, renovação antes da expiração, uma única chamada
/// ao provedor por conjunto de escopos ao mesmo tempo, métricas e log sem o token.
/// </summary>
/// <remarks>
/// <para>O token é renovado quando faltam menos de <see cref="RefreshBefore"/> (5 minutos) para expirar; para tokens curtos, a
/// antecedência é de um quarto da validade observada na obtenção (ex.: token de 5 minutos renovado com 75 segundos restantes),
/// então todo token é reaproveitado. Se a renovação falhar (inclusive por tempo limite do provedor) e o token atual ainda valer
/// por mais de <see cref="MinimumRemainingLifetime"/>, ele continua sendo usado (log 3122): uma instabilidade passageira do
/// provedor não derruba as chamadas entre serviços.</para>
/// <para>Com um <see cref="SecurityCircuitBreaker"/>, falhas repetidas abrem o circuito: as renovações seguintes falham na hora
/// (<see cref="SecurityCircuitOpenException"/> como causa) sem chamar o provedor, e a regra do token atual acima continua valendo.</para>
/// <para>Falhas do provedor sem token utilizável são registradas (evento 3120) e lançadas como
/// <see cref="SecurityTokenAcquisitionException"/>, sem detalhes de infraestrutura na mensagem; a exceção original fica em
/// <see cref="Exception.InnerException"/>. <see cref="OperationCanceledException"/> só passa direto quando o cancelamento foi
/// pedido pelo chamador; sem isso (tempo limite do <c>HttpClient</c> ou do Azure.Core) é falha do provedor.</para>
/// <para>Thread-safe. Depois do <see cref="Dispose()"/>, <see cref="GetTokenAsync"/> lança <see cref="ObjectDisposedException"/>.</para>
/// </remarks>
public abstract class CachingAccessTokenProvider : IAccessTokenProvider, IDisposable
{
    /// <summary>Antecedência máxima da renovação (tokens curtos usam um quarto da validade; ver <see cref="RefreshMargin"/>).</summary>
    public static readonly TimeSpan RefreshBefore = TimeSpan.FromMinutes(5);

    /// <summary>Validade restante mínima para continuar usando o token atual quando a renovação falha.</summary>
    public static readonly TimeSpan MinimumRemainingLifetime = TimeSpan.FromSeconds(30);

    /// <summary>Quantidade máxima de conjuntos de escopos distintos em cache (proteção contra crescimento sem limite).</summary>
    public const int MaxScopeSets = 1024;

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly ILogger? _logger;
    private readonly SecurityCircuitBreaker? _circuitBreaker;
    private volatile bool _disposed;

    /// <summary>Cria a base.</summary>
    /// <param name="providerName">Nome do provedor nas métricas e logs (ex.: <c>EntraId</c>).</param>
    /// <param name="time">Relógio (expiração dos tokens); padrão <see cref="TimeProvider.System"/>.</param>
    /// <param name="logger">Log (opcional; nunca recebe o token).</param>
    /// <param name="circuitBreaker">Circuit breaker do provedor (opcional; compartilhado entre os conjuntos de escopos).</param>
    /// <exception cref="ArgumentException"><paramref name="providerName"/> vazio.</exception>
    protected CachingAccessTokenProvider(string providerName, TimeProvider? time = null, ILogger? logger = null,
        SecurityCircuitBreaker? circuitBreaker = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ProviderName = providerName;
        _time = time ?? TimeProvider.System;
        _logger = logger;
        _circuitBreaker = circuitBreaker;
    }

    /// <summary>Nome do provedor nas métricas e logs (ex.: <c>EntraId</c>).</summary>
    protected string ProviderName { get; }

    /// <summary>Obtém um token novo no provedor (sem cache).</summary>
    /// <param name="scopes">Escopos pedidos.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    /// <returns>O token obtido.</returns>
    protected abstract ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken);

    /// <inheritdoc />
    /// <exception cref="ArgumentException">Sem escopo ou com escopo vazio.</exception>
    /// <exception cref="SecurityTokenAcquisitionException">O provedor falhou e não há token ainda válido em cache.</exception>
    /// <exception cref="ObjectDisposedException">Provedor descartado.</exception>
    public async ValueTask<AccessToken> GetTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        if (scopes.Count == 0 || scopes.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Informe ao menos um escopo válido.", nameof(scopes));
        ObjectDisposedException.ThrowIf(_disposed, this);

        string key = string.Join(' ', scopes.Order(StringComparer.Ordinal));
        long start = Stopwatch.GetTimestamp();
        if (!_entries.TryGetValue(key, out var entry))
        {
            if (_entries.Count >= MaxScopeSets)
                throw new InvalidOperationException($"Mais de {MaxScopeSets} conjuntos de escopos distintos: use conjuntos fixos (ex.: api://<id>/.default).");
            entry = _entries.GetOrAdd(key, static _ => new Entry());
        }

        if (IsFresh(entry.Cached))
        {
            SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: true, Stopwatch.GetElapsedTime(start).TotalSeconds, null);
            return entry.Cached!.Token;
        }

        await entry.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsFresh(entry.Cached))
            {
                SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: true, Stopwatch.GetElapsedTime(start).TotalSeconds, null);
                return entry.Cached!.Token;
            }

            using var activity = SecurityDiagnostics.StartTokenAcquisition(ProviderName);
            try
            {
                var token = _circuitBreaker is null
                    ? await AcquireTokenAsync(scopes, cancellationToken).ConfigureAwait(false)
                    : await _circuitBreaker.ExecuteAsync(ct => AcquireTokenAsync(scopes, ct), cancellationToken).ConfigureAwait(false);
                var now = _time.GetUtcNow();
                entry.Cached = new CachedToken(token, token.ExpiresOn - RefreshMargin(token.ExpiresOn - now));
                SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: false, Stopwatch.GetElapsedTime(start).TotalSeconds, null);
                return token;
            }
            // Cancelamento sem pedido do chamador é tempo limite do provedor (HttpClient, Azure.Core): tratado como falha
            catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
            {
                string errorType = exception.GetType().Name;
                activity?.SetStatus(ActivityStatusCode.Error);
                activity?.SetTag(SecurityDiagnostics.ErrorTypeTag, errorType);
                SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: false, Stopwatch.GetElapsedTime(start).TotalSeconds, errorType);

                if (entry.Cached?.Token is { } current && current.ExpiresOn - _time.GetUtcNow() > MinimumRemainingLifetime)
                {
                    if (_logger is not null)
                        SecurityLog.TokenRefreshFailedUsingCurrent(_logger, exception, ProviderName, errorType);
                    return current;
                }

                if (_logger is not null)
                    SecurityLog.TokenAcquisitionFailed(_logger, exception, ProviderName, errorType);
                throw new SecurityTokenAcquisitionException(exception);
            }
        }
        finally
        {
            entry.Lock.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <summary>Libera os recursos.</summary>
    /// <param name="disposing"><c>true</c> quando chamado por <see cref="Dispose()"/>.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (!disposing || _disposed)
            return;

        _disposed = true;
        foreach (var entry in _entries.Values)
            entry.Cached = null;
        _entries.Clear();
    }

    /// <summary>
    /// Antecedência da renovação para um token com a <paramref name="lifetime"/> observada na obtenção: um quarto da validade,
    /// limitado a <see cref="RefreshBefore"/>. Um token de até 5 minutos (padrão do Keycloak, por exemplo) também é reaproveitado.
    /// </summary>
    public static TimeSpan RefreshMargin(TimeSpan lifetime) =>
        lifetime <= TimeSpan.Zero ? TimeSpan.Zero : TimeSpan.FromTicks(Math.Min(RefreshBefore.Ticks, lifetime.Ticks / 4));

    private bool IsFresh(CachedToken? cached) => cached is not null && _time.GetUtcNow() < cached.RefreshAt;

    private sealed class Entry
    {
        // Não descartado: um GetTokenAsync em andamento durante o Dispose ainda chama Release; o SemaphoreSlim sem
        // AvailableWaitHandle não guarda recurso nativo
        public SemaphoreSlim Lock { get; } = new(1, 1);

        public volatile CachedToken? Cached;
    }

    /// <summary>Token em cache e o instante da renovação (calculado na obtenção, com a validade observada).</summary>
    private sealed record CachedToken(AccessToken Token, DateTimeOffset RefreshAt);
}

/// <summary>
/// Falha ao obter token de serviço no provedor de identidade (HTTP 502 pelo <see cref="AppException"/>, código
/// <see cref="SecurityErrors.ProviderFailureCode"/>). A mensagem não traz detalhes de infraestrutura.
/// </summary>
public sealed class SecurityTokenAcquisitionException : AppException
{
    private static readonly string DefaultMessage = SecurityErrors.ProviderFailure().Message;

    /// <summary>Cria a exceção.</summary>
    public SecurityTokenAcquisitionException() : this(DefaultMessage)
    {
    }

    /// <summary>Cria a exceção com a causa.</summary>
    /// <param name="innerException">Falha original (não exposta ao cliente).</param>
    public SecurityTokenAcquisitionException(Exception innerException) : this(DefaultMessage, innerException)
    {
    }

    /// <summary>Cria a exceção com mensagem.</summary>
    /// <param name="message">Mensagem (sem detalhes de infraestrutura).</param>
    public SecurityTokenAcquisitionException(string message)
        : base(SecurityErrors.ProviderFailureCode, message, ErrorType.ExternalService)
    {
    }

    /// <summary>Cria a exceção com mensagem e causa.</summary>
    /// <param name="message">Mensagem (sem detalhes de infraestrutura).</param>
    /// <param name="innerException">Falha original (não exposta ao cliente).</param>
    public SecurityTokenAcquisitionException(string message, Exception innerException)
        : base(SecurityErrors.ProviderFailureCode, message, ErrorType.ExternalService, innerException)
    {
    }
}
