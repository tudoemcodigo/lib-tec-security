using Microsoft.Extensions.Options;

namespace TEC.Security.Benchmarks;

/// <summary><see cref="IOptionsMonitor{T}"/> com valor fixo (sem recarga), para montar os componentes sem contêiner.</summary>
internal sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
{
    public T CurrentValue => value;

    public T Get(string? name) => value;

    public IDisposable? OnChange(Action<T, string?> listener) => null;
}
