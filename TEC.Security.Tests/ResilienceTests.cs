using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Security.Abstractions;
using TEC.Security.DependencyInjection;
using TEC.Security.EntraId;
using TEC.Security.EntraId.Internal;
using TEC.Security.Resilience;
using TEC.Security.Tokens;

namespace TEC.Security.Tests;

public class ResilienceTests
{
    private const string TokenEndpoint = "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000001/oauth2/v2.0/token";
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static EntraIdResilienceOptions Fast(int maxRetries = 2) => new()
    {
        MaxRetries = maxRetries,
        MaxRetryDelay = TimeSpan.FromMilliseconds(5)
    };

    private static SecurityCircuitBreakerOptions Sensitive() => new()
    {
        MinimumThroughput = 2,
        FailureRatio = 0.5,
        BreakDuration = TimeSpan.FromSeconds(30)
    };

    private static Task<AccessToken> CallAsync(EntraIdTokenEndpoint endpoint) =>
        endpoint.OnBehalfOfAsync(TokenEndpoint, "client", new ClientAuthentication("segredo", null), "token-do-usuario", ["api://x/.default"], default);

    // ================================================================ retentativa do On-Behalf-Of

    [Test]
    [Arguments(HttpStatusCode.ServiceUnavailable)]
    [Arguments(HttpStatusCode.TooManyRequests)]
    [Arguments(HttpStatusCode.InternalServerError)]
    [Arguments(HttpStatusCode.RequestTimeout)]
    public async Task Transient_status_is_retried_until_success(HttpStatusCode status)
    {
        var handler = new ScriptedHandler(_ => Respond(status, "{}"), _ => Ok());
        using var http = new HttpClient(handler);
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast());

        var token = await CallAsync(endpoint);

        await Assert.That(token.Token).IsEqualTo("novo");
        await Assert.That(handler.Calls).IsEqualTo(2);
        // Cada tentativa é uma requisição nova, com o mesmo formulário
        await Assert.That(handler.Bodies.Distinct().Count()).IsEqualTo(1);
    }

    [Test]
    public async Task Network_failure_is_retried_and_reported_after_attempts_are_exhausted()
    {
        var handler = new ScriptedHandler(_ => throw new HttpRequestException("conexão recusada"));
        using var http = new HttpClient(handler);
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast(maxRetries: 2));

        await Assert.That(async () => await CallAsync(endpoint)).Throws<HttpRequestException>();
        await Assert.That(handler.Calls).IsEqualTo(3);
    }

    [Test]
    public async Task HttpClient_timeout_is_retried()
    {
        var handler = new ScriptedHandler(_ => throw new TaskCanceledException("tempo limite"), _ => Ok());
        using var http = new HttpClient(handler);
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast());

        await Assert.That((await CallAsync(endpoint)).Token).IsEqualTo("novo");
        await Assert.That(handler.Calls).IsEqualTo(2);
    }

    [Test]
    [Arguments("invalid_grant")]
    [Arguments("interaction_required")]
    [Arguments("invalid_client")]
    public async Task OAuth_errors_are_never_retried(string error)
    {
        var handler = new ScriptedHandler(_ => Respond(HttpStatusCode.BadRequest, $$"""{"error":"{{error}}"}"""));
        using var http = new HttpClient(handler);
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast());

        var exception = await Assert.That(async () => await CallAsync(endpoint)).Throws<HttpRequestException>();
        await Assert.That(exception!.Message).Contains(error);
        await Assert.That(handler.Calls).IsEqualTo(1);
    }

    [Test]
    public async Task Retry_after_above_limit_gives_up_immediately()
    {
        var handler = new ScriptedHandler(_ =>
        {
            var response = Respond(HttpStatusCode.TooManyRequests, "{}");
            response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromMinutes(5));
            return response;
        });
        using var http = new HttpClient(handler);
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast());

        await Assert.That(async () => await CallAsync(endpoint)).Throws<HttpRequestException>();
        await Assert.That(handler.Calls).IsEqualTo(1);
    }

    [Test]
    public async Task Caller_cancellation_is_not_retried()
    {
        using var cts = new CancellationTokenSource();
        var handler = new ScriptedHandler(_ =>
        {
            cts.Cancel();
            throw new TaskCanceledException();
        });
        using var http = new HttpClient(handler);
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast());

        await Assert.That(async () => await endpoint.OnBehalfOfAsync(TokenEndpoint, "client", new ClientAuthentication("s", null), "u",
            ["api://x/.default"], cts.Token)).Throws<OperationCanceledException>();
        await Assert.That(handler.Calls).IsEqualTo(1);
    }

    // ================================================================ circuit breaker do On-Behalf-Of

    [Test]
    public async Task On_behalf_of_circuit_opens_on_repeated_unavailability()
    {
        var clock = new Clock(Start);
        bool down = true;
        var handler = new ScriptedHandler(_ => down ? Respond(HttpStatusCode.ServiceUnavailable, "{}") : Ok());
        using var http = new HttpClient(handler);
        var circuit = new SecurityCircuitBreaker("EntraId.OnBehalfOf", Sensitive(), EntraIdTokenEndpoint.IsTransient, clock);
        var endpoint = new EntraIdTokenEndpoint(http, clock, Fast(maxRetries: 0), circuit);

        await Assert.That(async () => await CallAsync(endpoint)).Throws<HttpRequestException>();
        await Assert.That(async () => await CallAsync(endpoint)).Throws<HttpRequestException>();
        await Assert.That(circuit.IsOpen).IsTrue();

        await Assert.That(async () => await CallAsync(endpoint)).Throws<SecurityCircuitOpenException>();
        await Assert.That(handler.Calls).IsEqualTo(2);

        down = false;
        clock.Now = Start.AddSeconds(31);
        await Assert.That((await CallAsync(endpoint)).Token).IsEqualTo("novo");
        await Assert.That(circuit.IsOpen).IsFalse();
    }

    [Test]
    public async Task User_errors_do_not_open_the_on_behalf_of_circuit()
    {
        var handler = new ScriptedHandler(_ => Respond(HttpStatusCode.BadRequest, """{"error":"invalid_grant"}"""));
        using var http = new HttpClient(handler);
        var circuit = new SecurityCircuitBreaker("EntraId.OnBehalfOf", Sensitive(), EntraIdTokenEndpoint.IsTransient, new Clock(Start));
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast(), circuit);

        for (int i = 0; i < 10; i++)
            await Assert.That(async () => await CallAsync(endpoint)).Throws<HttpRequestException>();

        await Assert.That(circuit.IsOpen).IsFalse();
        await Assert.That(handler.Calls).IsEqualTo(10);
    }

    // ================================================================ circuit breaker dos tokens da aplicação

    [Test]
    public async Task Access_token_circuit_fails_fast_and_keeps_using_the_current_token()
    {
        var clock = new Clock(Start);
        var provider = new FlakyProvider(clock, new SecurityCircuitBreaker("Fake", Sensitive(), timeProvider: clock));
        var first = await provider.GetTokenAsync(["a/.default"], default);

        // Token perto do fim (renovação), mas ainda válido: o provedor cai
        clock.Now = Start.AddMinutes(56);
        provider.Fail = true;
        for (int i = 0; i < 2; i++)
            await Assert.That((await provider.GetTokenAsync(["a/.default"], default)).Token).IsEqualTo(first.Token);
        int calls = provider.Calls;

        // Circuito aberto: o token atual continua em uso, sem chamar o provedor
        await Assert.That((await provider.GetTokenAsync(["a/.default"], default)).Token).IsEqualTo(first.Token);
        await Assert.That(provider.Calls).IsEqualTo(calls);

        // Sem token utilizável: falha na hora com a causa
        var exception = await Assert.That(async () => await provider.GetTokenAsync(["b/.default"], default))
            .Throws<SecurityTokenAcquisitionException>();
        await Assert.That(exception!.InnerException).IsTypeOf<SecurityCircuitOpenException>();
        await Assert.That(provider.Calls).IsEqualTo(calls);
    }

    [Test]
    public async Task Client_assertion_is_created_for_each_attempt()
    {
        var handler = new ScriptedHandler(_ => Respond(HttpStatusCode.ServiceUnavailable, "{}"), _ => Ok());
        using var http = new HttpClient(handler);
        var endpoint = new EntraIdTokenEndpoint(http, new Clock(Start), Fast());
        int created = 0;

        await endpoint.OnBehalfOfAsync(TokenEndpoint, "client",
            _ => Task.FromResult(new ClientAuthentication(null, "assertion-" + Interlocked.Increment(ref created))),
            "token-do-usuario", ["api://x/.default"], default);

        await Assert.That(created).IsEqualTo(2);
        await Assert.That(handler.Bodies.ElementAt(0)).Contains("assertion-1");
        await Assert.That(handler.Bodies.ElementAt(1)).Contains("assertion-2");
    }

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
    public async Task Cancellation_while_closed_does_not_open_circuit()
    {
        var circuit = new SecurityCircuitBreaker("Fake", Sensitive(), timeProvider: new Clock(Start));

        for (int i = 0; i < 10; i++)
            await Assert.That(async () => await circuit.ExecuteAsync<int>(_ => throw new OperationCanceledException(), default))
                .Throws<OperationCanceledException>();

        await Assert.That(circuit.IsOpen).IsFalse();
    }

    // ================================================================ opções

    [Test]
    [Arguments(-1, 1.0)]
    [Arguments(6, 1.0)]
    [Arguments(2, 61.0)]
    public async Task Out_of_range_retry_options_are_rejected(int maxRetries, double maxDelaySeconds)
    {
        var options = new EntraIdResilienceOptions { MaxRetries = maxRetries, MaxRetryDelay = TimeSpan.FromSeconds(maxDelaySeconds) };

        await Assert.That(() => options.Validate("X")).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Out_of_range_circuit_options_are_rejected_only_when_enabled()
    {
        var options = new SecurityCircuitBreakerOptions { MinimumThroughput = 1 };

        await Assert.That(() => options.Validate("X")).Throws<InvalidOperationException>();
        options.Enabled = false;
        options.Validate("X");
        await Assert.That(SecurityCircuitBreaker.Create("P", options)).IsNull();
    }

    [Test]
    public async Task Resilience_is_bound_from_configuration_and_circuits_are_registered()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["EntraId:Client:Credential:Type"] = "ManagedIdentity",
            ["EntraId:Client:Resilience:MaxRetries"] = "1",
            ["EntraId:Client:Resilience:CircuitBreaker:BreakDuration"] = "00:00:05"
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecSecurity(configuration, security => security.AddEntraIdClient(configuration.GetSection("EntraId:Client")));
        using var provider = services.BuildServiceProvider();

        var registration = provider.GetRequiredService<EntraIdClientRegistration>();

        await Assert.That(registration.Options.Resilience.MaxRetries).IsEqualTo(1);
        await Assert.That(registration.Options.Resilience.CircuitBreaker.BreakDuration).IsEqualTo(TimeSpan.FromSeconds(5));
        await Assert.That(registration.AccessTokenCircuit).IsNotNull();
        await Assert.That(registration.OnBehalfOfCircuit).IsNotNull();
    }

    [Test]
    public async Task Invalid_resilience_configuration_fails_at_startup()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["EntraId:Client:Credential:Type"] = "ManagedIdentity",
            ["EntraId:Client:Resilience:CircuitBreaker:FailureRatio"] = "2"
        }).Build();
        var services = new ServiceCollection();

        await Assert.That(() => services.AddTecSecurity(configuration,
            security => security.AddEntraIdClient(configuration.GetSection("EntraId:Client")))).Throws<InvalidOperationException>();
    }

    // ================================================================ dublês

    private static HttpResponseMessage Respond(HttpStatusCode status, string json) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private static HttpResponseMessage Ok() => Respond(HttpStatusCode.OK, """{"access_token":"novo","expires_in":3600}""");

    /// <summary>Responde em sequência; a última resposta se repete.</summary>
    private sealed class ScriptedHandler(params Func<HttpRequestMessage, HttpResponseMessage>[] responses) : HttpMessageHandler
    {
        private int _calls;

        public int Calls => _calls;

        public ConcurrentQueue<string> Bodies { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            int call = Interlocked.Increment(ref _calls);
            Bodies.Enqueue(request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken));
            return responses[Math.Min(call, responses.Length) - 1](request);
        }
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;

        public override long GetTimestamp() => Now.UtcTicks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
    }

    private sealed class FlakyProvider(TimeProvider clock, SecurityCircuitBreaker circuit)
        : CachingAccessTokenProvider("Fake", clock, circuitBreaker: circuit)
    {
        private readonly TimeProvider _clock = clock;
        private int _calls;

        public bool Fail { get; set; }

        public int Calls => _calls;

        protected override ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            if (Fail)
                throw new HttpRequestException("provedor fora do ar");
            return ValueTask.FromResult(new AccessToken("token-" + _calls, _clock.GetUtcNow().AddHours(1)));
        }
    }
}
