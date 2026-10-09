using Microsoft.Extensions.Logging;
using Polly;
using Polly.CircuitBreaker;
using TEC.Security.Diagnostics;
using TEC.Security.Internal;

namespace TEC.Security.Resilience;

/// <summary>
/// Circuit breaker de um destino (ex.: o endpoint de token do provedor de identidade). Uso pelos pacotes de provedor; uma
/// instância por destino, compartilhada (singleton). Thread-safe.
/// </summary>
/// <remarks>
/// Cancelamento pedido pelo chamador não abre o circuito; na chamada de teste (meia-abertura) ele conta como falha, para o
/// circuito não fechar sem resposta do destino. Com o circuito aberto, <see cref="ExecuteAsync{T}"/> lança
/// <see cref="SecurityCircuitOpenException"/> sem executar a chamada.
/// </remarks>
public sealed class SecurityCircuitBreaker
{
    private readonly ResiliencePipeline _pipeline;
    private readonly CircuitBreakerStateProvider _state = new();

    /// <summary>Cria o circuit breaker.</summary>
    /// <param name="providerName">Nome do provedor nas métricas e logs (ex.: <c>EntraId</c>).</param>
    /// <param name="options">Opções (validadas aqui; <see cref="SecurityCircuitBreakerOptions.Enabled"/> é ignorado: para respeitá-lo use <see cref="Create"/>).</param>
    /// <param name="countsAsFailure">Quais exceções contam como falha do destino. Padrão: todas (exceto cancelamento).</param>
    /// <param name="timeProvider">Relógio. Padrão: <see cref="TimeProvider.System"/>.</param>
    /// <param name="logger">Log das mudanças de estado (opcional).</param>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public SecurityCircuitBreaker(string providerName, SecurityCircuitBreakerOptions options, Func<Exception, bool>? countsAsFailure = null,
        TimeProvider? timeProvider = null, ILogger? logger = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(providerName);
        ArgumentNullException.ThrowIfNull(options);
        options.ValidateValues("CircuitBreaker");

        ProviderName = providerName;
        var isFailure = countsAsFailure ?? (static _ => true);
        _pipeline = new ResiliencePipelineBuilder { TimeProvider = timeProvider ?? TimeProvider.System }
            .AddCircuitBreaker(new CircuitBreakerStrategyOptions
            {
                FailureRatio = options.FailureRatio,
                MinimumThroughput = options.MinimumThroughput,
                SamplingDuration = options.SamplingDuration,
                BreakDuration = options.BreakDuration,
                StateProvider = _state,
                // Para o Polly, o que não é falha conta como sucesso (e fecha o circuito na meia-abertura): uma chamada de teste
                // cancelada não teve resposta do destino, então conta como falha e o circuito volta a abrir
                ShouldHandle = args => ValueTask.FromResult(args.Outcome.Exception is { } ex
                    && (ex is OperationCanceledException ? _state.CircuitState == CircuitState.HalfOpen : isFailure(ex))),
                OnOpened = args =>
                {
                    SecurityDiagnostics.RecordCircuitState(ProviderName, SecurityDiagnostics.CircuitOpen);
                    if (logger is not null)
                        SecurityLog.CircuitOpened(logger, ProviderName, args.BreakDuration.TotalSeconds);
                    return default;
                },
                OnHalfOpened = _ =>
                {
                    SecurityDiagnostics.RecordCircuitState(ProviderName, SecurityDiagnostics.CircuitHalfOpen);
                    if (logger is not null)
                        SecurityLog.CircuitHalfOpened(logger, ProviderName);
                    return default;
                },
                OnClosed = _ =>
                {
                    SecurityDiagnostics.RecordCircuitState(ProviderName, SecurityDiagnostics.CircuitClosed);
                    if (logger is not null)
                        SecurityLog.CircuitClosed(logger, ProviderName);
                    return default;
                }
            })
            .Build();
    }

    /// <summary>Nome do provedor.</summary>
    public string ProviderName { get; }

    /// <summary>Indica se o circuito está aberto (chamadas recusadas sem chegar ao destino).</summary>
    public bool IsOpen => _state.CircuitState is CircuitState.Open or CircuitState.Isolated;

    /// <summary>
    /// Cria o circuit breaker conforme as opções, ou <c>null</c> quando <see cref="SecurityCircuitBreakerOptions.Enabled"/> é
    /// <c>false</c> (ou as opções não foram informadas).
    /// </summary>
    /// <exception cref="InvalidOperationException">Opções inválidas.</exception>
    public static SecurityCircuitBreaker? Create(string providerName, SecurityCircuitBreakerOptions? options, Func<Exception, bool>? countsAsFailure = null,
        TimeProvider? timeProvider = null, ILogger? logger = null)
    {
        if (options is null || !options.Enabled)
            return null;
        return new SecurityCircuitBreaker(providerName, options, countsAsFailure, timeProvider, logger);
    }

    /// <summary>Executa a chamada pelo circuito.</summary>
    /// <param name="call">Chamada ao destino.</param>
    /// <param name="cancellationToken">Cancelamento.</param>
    /// <returns>O resultado da chamada.</returns>
    /// <exception cref="SecurityCircuitOpenException">Circuito aberto: a chamada não foi feita.</exception>
    public async ValueTask<T> ExecuteAsync<T>(Func<CancellationToken, ValueTask<T>> call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        try
        {
            return await _pipeline.ExecuteAsync(static (state, ct) => state(ct), call, cancellationToken).ConfigureAwait(false);
        }
        catch (BrokenCircuitException exception)
        {
            throw new SecurityCircuitOpenException(ProviderName, exception);
        }
    }
}

/// <summary>
/// Chamada recusada sem chegar ao provedor de identidade: o circuito está aberto depois de falhas repetidas. Os provedores a
/// convertem em <c>SecurityTokenAcquisitionException</c> (HTTP 502) e ela fica em <see cref="Exception.InnerException"/>.
/// </summary>
public sealed class SecurityCircuitOpenException : Exception
{
    /// <summary>Cria a exceção.</summary>
    public SecurityCircuitOpenException() : base("Circuito aberto: o provedor de identidade falhou repetidas vezes.")
    {
    }

    /// <summary>Cria a exceção com mensagem.</summary>
    public SecurityCircuitOpenException(string message) : base(message)
    {
    }

    /// <summary>Cria a exceção com mensagem e causa.</summary>
    public SecurityCircuitOpenException(string message, Exception innerException) : base(message, innerException)
    {
    }

    internal SecurityCircuitOpenException(string providerName, BrokenCircuitException innerException)
        : base($"Circuito aberto para {providerName}: chamada recusada após falhas repetidas do provedor de identidade.", innerException)
    {
    }
}
