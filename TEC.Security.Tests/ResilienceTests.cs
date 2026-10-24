using System.Net;
using TEC.Security.Abstractions;
using TEC.Security.Resilience;
using TEC.Security.Tokens;

namespace TEC.Security.Tests;

public class ResilienceTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static SecurityCircuitBreakerOptions Sensitive() => new()
    {
        MinimumThroughput = 2,
        FailureRatio = 0.5,
        BreakDuration = TimeSpan.FromSeconds(30)
    };

    [Test]
    public async Task Cancelled_probe_keeps_circuit_open()
    {
        var clock = new Clock(Start);
        var circuit = new SecurityCircuitBreaker("Fake", Sensitive(), timeProvider: clock);
        for (int i = 0; i < 2; i++)
            await Assert.That(async () => await circuit.ExecuteAsync<int>(_ => throw new HttpRequestException("fora"), default))
                .Throws<HttpRequestException>();
        await Assert.That(circuit.IsOpen).IsTrue();

        // Chamada de teste cancelada: sem resposta do destino, o circuito não pode fechar
        clock.Now = Start.AddSeconds(31);
        await Assert.That(async () => await circuit.ExecuteAsync<int>(_ => throw new OperationCanceledException(), default))
            .Throws<OperationCanceledException>();

        await Assert.That(circuit.IsOpen).IsTrue();
        await Assert.That(async () => await circuit.ExecuteAsync(_ => ValueTask.FromResult(1), default)).Throws<SecurityCircuitOpenException>();
    }

    [Test]
    public async Task Caller_cancellation_while_closed_does_not_open_circuit()
    {
        var circuit = new SecurityCircuitBreaker("Fake", Sensitive(), timeProvider: new Clock(Start));

        for (int i = 0; i < 10; i++)
        {
            using var cts = new CancellationTokenSource();
            await Assert.That(async () => await circuit.ExecuteAsync<int>(ct =>
            {
                cts.Cancel();
                throw new OperationCanceledException(ct);
            }, cts.Token)).Throws<OperationCanceledException>();
        }

        await Assert.That(circuit.IsOpen).IsFalse();
    }

    [Test]
    public async Task Timeout_without_caller_cancellation_counts_as_failure()
    {
        // SEC-01: tempo limite do HttpClient chega como OperationCanceledException sem cancelamento do chamador
        var circuit = new SecurityCircuitBreaker("Fake", Sensitive(), timeProvider: new Clock(Start));

        for (int i = 0; i < 2; i++)
            await Assert.That(async () => await circuit.ExecuteAsync<int>(_ => throw new TaskCanceledException("tempo limite"), default))
                .Throws<TaskCanceledException>();

        await Assert.That(circuit.IsOpen).IsTrue();
    }

    [Test]
    public async Task Provider_timeout_keeps_current_token_and_becomes_acquisition_failure()
    {
        // SEC-01: antes o tempo limite escapava como TaskCanceledException, sem usar o token atual ainda válido
        var clock = new Clock(Start);
        using var provider = new TimeoutProvider(clock);
        var first = await provider.GetTokenAsync(["a/.default"], default);

        clock.Now = Start.AddMinutes(56);
        provider.TimesOut = true;
        var current = await provider.GetTokenAsync(["a/.default"], default);
        var exception = await Assert.That(async () => await provider.GetTokenAsync(["b/.default"], default))
            .Throws<SecurityTokenAcquisitionException>();

        await Assert.That(current.Token).IsEqualTo(first.Token);
        await Assert.That(exception!.InnerException).IsTypeOf<TaskCanceledException>();
    }

    [Test]
    public async Task Caller_cancellation_still_propagates_from_token_provider()
    {
        using var provider = new TimeoutProvider(new Clock(Start)) { TimesOut = true };
        using var cts = new CancellationTokenSource();
        provider.OnCall = cts.Cancel;

        await Assert.That(async () => await provider.GetTokenAsync(["a/.default"], cts.Token)).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task Short_lived_token_is_reused_until_a_quarter_of_its_lifetime_remains()
    {
        // SEC-02: token de 5 minutos (padrão do Keycloak) nascia "vencido" para o cache e toda chamada ia ao provedor
        var clock = new Fakes.ManualTimeProvider(Start);
        using var provider = new Fakes.CountingTokenProvider(clock, TimeSpan.FromMinutes(5));

        for (int i = 0; i < 10; i++)
            await provider.GetTokenAsync(["a/.default"], default);
        int afterBurst = provider.Calls;
        clock.Now = Start.AddMinutes(3.5);   // restam 90 s: acima de 1/4 da validade (75 s)
        await provider.GetTokenAsync(["a/.default"], default);
        int beforeMargin = provider.Calls;
        clock.Now = Start.AddMinutes(4);     // restam 60 s: renova
        await provider.GetTokenAsync(["a/.default"], default);

        await Assert.That(afterBurst).IsEqualTo(1);
        await Assert.That(beforeMargin).IsEqualTo(1);
        await Assert.That(provider.Calls).IsEqualTo(2);
        await Assert.That(CachingAccessTokenProvider.RefreshMargin(TimeSpan.FromHours(1))).IsEqualTo(CachingAccessTokenProvider.RefreshBefore);
        await Assert.That(CachingAccessTokenProvider.RefreshMargin(TimeSpan.FromMinutes(5))).IsEqualTo(TimeSpan.FromSeconds(75));
    }

    private sealed class TimeoutProvider : CachingAccessTokenProvider
    {
        private readonly TimeProvider _clock;

        public TimeoutProvider(TimeProvider timeProvider) : base("Timeout", timeProvider, NullLogger())
        {
            _clock = timeProvider;
        }

        public bool TimesOut { get; set; }
        public Action? OnCall { get; set; }

        protected override ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
        {
            OnCall?.Invoke();
            if (TimesOut)
                throw new TaskCanceledException("tempo limite");
            return ValueTask.FromResult(new AccessToken("token-" + string.Join('-', scopes), _clock.GetUtcNow().AddHours(1)));
        }

        private static Microsoft.Extensions.Logging.ILogger NullLogger() => Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    private sealed class Clock(DateTimeOffset initial) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = initial;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
