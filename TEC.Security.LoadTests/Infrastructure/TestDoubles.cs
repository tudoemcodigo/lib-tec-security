using Microsoft.Extensions.Options;
using TEC.Security.Abstractions;
using TEC.Security.Tokens;

namespace TEC.Security.LoadTests.Infrastructure;

/// <summary><see cref="IOptionsMonitor{T}"/> manual, com troca de valor e aviso de mudança (simula a recarga do appsettings).</summary>
public sealed class ManualOptionsMonitor<T>(T value) : IOptionsMonitor<T>
{
    private readonly object _gate = new();
    private Action<T, string?>[] _listeners = [];

    public T CurrentValue { get; private set; } = value;

    public T Get(string? name) => CurrentValue;

    public IDisposable OnChange(Action<T, string?> listener)
    {
        lock (_gate)
            _listeners = [.. _listeners, listener];
        return new Subscription(() =>
        {
            lock (_gate)
                _listeners = [.. _listeners.Where(l => l != listener)];
        });
    }

    public void Set(T value)
    {
        CurrentValue = value;
        foreach (var listener in _listeners)
            listener(value, Options.DefaultName);
    }

    private sealed class Subscription(Action dispose) : IDisposable
    {
        public void Dispose() => dispose();
    }
}

/// <summary>Relógio manual (thread-safe).</summary>
public sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
{
    private long _ticks = now.UtcTicks;

    public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref _ticks), TimeSpan.Zero);

    public void Advance(TimeSpan delta) => Interlocked.Add(ref _ticks, delta.Ticks);
}

/// <summary>
/// Store de permissões que simula uma consulta ao banco (latência configurável). As permissões derivam do id e dos papéis,
/// para o teste conferir que cada identidade recebeu exatamente as suas.
/// </summary>
public sealed class SimulatedDatabasePermissionStore(PermissionStoreLatency latency) : IPermissionStore
{
    private long _calls;

    /// <summary>Consultas feitas à "fonte" (as que o cache não evitou).</summary>
    public long Calls => Interlocked.Read(ref _calls);

    public async ValueTask<IReadOnlyCollection<string>> GetPermissionsAsync(PermissionContext context, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        if (latency.Value > TimeSpan.Zero)
            await Task.Delay(latency.Value, cancellationToken);
        else
            await Task.Yield();

        return Expected(context.UserId, context.Roles);
    }

    /// <summary>Permissões que a "fonte" devolve para a identidade.</summary>
    public static IReadOnlyCollection<string> Expected(string userId, IEnumerable<string> roles) =>
        [$"perfil:{Math.Abs(userId.GetHashCode(StringComparison.Ordinal)) % 97}", .. roles.Select(r => $"{r}:executar")];
}

/// <summary>Latência de cada consulta do <see cref="SimulatedDatabasePermissionStore"/> (registrada no contêiner).</summary>
public sealed record PermissionStoreLatency(TimeSpan Value);

/// <summary>Provedor de token de serviço com latência e contagem de chamadas ao "provedor de identidade".</summary>
public sealed class CountingTokenProvider(TimeProvider clock, TimeSpan lifetime, TimeSpan latency) : CachingAccessTokenProvider("Carga", clock)
{
    private readonly TimeProvider _clock = clock;
    private long _calls;

    public long Calls => Interlocked.Read(ref _calls);

    protected override async ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
    {
        long call = Interlocked.Increment(ref _calls);
        if (latency > TimeSpan.Zero)
            await Task.Delay(latency, cancellationToken);
        return new AccessToken($"token-{call}-{string.Join('+', scopes)}", _clock.GetUtcNow().Add(lifetime));
    }
}
