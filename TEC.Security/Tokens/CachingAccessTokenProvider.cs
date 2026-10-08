using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using TEC.Core.Common.Results;
using TEC.Core.Exceptions;
using TEC.Security.Abstractions;
using TEC.Security.Common;
using TEC.Security.Diagnostics;
using TEC.Security.Internal;

namespace TEC.Security.Tokens;

/// <summary>
/// Base para provedores de token de serviço: cache por conjunto de escopos, renovação antes da expiração, uma única chamada
/// ao provedor por conjunto de escopos ao mesmo tempo, métricas e log sem o token.
/// </summary>
/// <remarks>
/// <para>O token é renovado quando faltam menos de <see cref="RefreshBefore"/> (5 minutos) para expirar. Se a renovação falhar
/// e o token atual ainda valer por mais de <see cref="MinimumRemainingLifetime"/>, ele continua sendo usado (log 3122): uma
/// instabilidade passageira do provedor não derruba as chamadas entre serviços.</para>
/// <para>Falhas do provedor sem token utilizável são registradas (evento 3120) e lançadas como
/// <see cref="SecurityTokenAcquisitionException"/>, sem detalhes de infraestrutura na mensagem; a exceção original fica em
/// <see cref="Exception.InnerException"/>.</para>
/// <para>Thread-safe. Depois do <see cref="Dispose()"/>, <see cref="GetTokenAsync"/> lança <see cref="ObjectDisposedException"/>.</para>
/// </remarks>
public abstract class CachingAccessTokenProvider : IAccessTokenProvider, IDisposable
{
    /// <summary>Antecedência da renovação.</summary>
    public static readonly TimeSpan RefreshBefore = TimeSpan.FromMinutes(5);

    /// <summary>Validade restante mínima para continuar usando o token atual quando a renovação falha.</summary>
    public static readonly TimeSpan MinimumRemainingLifetime = TimeSpan.FromSeconds(30);

    /// <summary>Quantidade máxima de conjuntos de escopos distintos em cache (proteção contra crescimento sem limite).</summary>
    public const int MaxScopeSets = 1024;

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private readonly ILogger? _logger;
    private volatile bool _disposed;

    /// <summary>Cria a base.</summary>
    /// <param name="providerName">Nome do provedor nas métricas e logs (ex.: <c>EntraId</c>).</param>
    /// <param name="time">Relógio (expiração dos tokens); padrão <see cref="TimeProvider.System"/>.</param>
    /// <param name="logger">Log (opcional; nunca recebe o token).</param>
    /// <exception cref="ArgumentException"><paramref name="providerName"/> vazio.</exception>
    protected CachingAccessTokenProvider(string providerName, TimeProvider? time = null, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ProviderName = providerName;
        _time = time ?? TimeProvider.System;
        _logger = logger;
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

        if (IsFresh(entry.Token))
        {
            SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: true, Stopwatch.GetElapsedTime(start).TotalSeconds, null);
            return entry.Token!;
        }

        await entry.Lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsFresh(entry.Token))
            {
                SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: true, Stopwatch.GetElapsedTime(start).TotalSeconds, null);
                return entry.Token!;
            }

            using var activity = SecurityDiagnostics.StartTokenAcquisition(ProviderName);
            try
            {
                var token = await AcquireTokenAsync(scopes, cancellationToken).ConfigureAwait(false);
                entry.Token = token;
                SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: false, Stopwatch.GetElapsedTime(start).TotalSeconds, null);
                return token;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                string errorType = exception.GetType().Name;
                activity?.SetStatus(ActivityStatusCode.Error);
                activity?.SetTag(SecurityDiagnostics.ErrorTypeTag, errorType);
                SecurityDiagnostics.RecordTokenAcquisition(ProviderName, cacheHit: false, Stopwatch.GetElapsedTime(start).TotalSeconds, errorType);

                if (entry.Token is { } current && current.ExpiresOn - _time.GetUtcNow() > MinimumRemainingLifetime)
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
            entry.Token = null;
        _entries.Clear();
    }

    private bool IsFresh(AccessToken? token) => token is not null && token.ExpiresOn - _time.GetUtcNow() > RefreshBefore;

    private sealed class Entry
    {
        // Não descartado: um GetTokenAsync em andamento durante o Dispose ainda chama Release; o SemaphoreSlim sem
        // AvailableWaitHandle não guarda recurso nativo
        public SemaphoreSlim Lock { get; } = new(1, 1);

        public volatile AccessToken? Token;
    }
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
