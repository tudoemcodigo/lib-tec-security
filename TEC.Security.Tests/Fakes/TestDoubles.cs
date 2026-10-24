using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Vault.Abstractions;
using TEC.Vault.Certificates;
using TEC.Vault.Keys;
using TEC.Core.Common.Results;
using TEC.Security.Abstractions;
using TEC.Security.Tokens;

namespace TEC.Security.Tests.Fakes;

/// <summary>Logger que guarda as mensagens formatadas (para conferir que segredos não vão para o log).</summary>
internal sealed class TestLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<(LogLevel Level, int EventId, string Message)> Entries { get; } = new();

    public string All => string.Join('\n', Entries.Select(e => e.Message));

    public ILogger CreateLogger(string categoryName) => new Logger(this);

    public void Dispose()
    {
    }

    private sealed class Logger(TestLoggerProvider owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            owner.Entries.Enqueue((logLevel, eventId.Id, formatter(state, exception) + (exception is null ? "" : " | " + exception)));
    }
}

/// <summary><see cref="IOptionsMonitor{T}"/> manual, com troca de valor e aviso de mudança.</summary>
internal sealed class TestOptionsMonitor<T>(T value) : IOptionsMonitor<T>
{
    private readonly List<Action<T, string?>> _listeners = [];

    public T CurrentValue { get; private set; } = value;

    public T Get(string? name) => CurrentValue;

    public IDisposable OnChange(Action<T, string?> listener)
    {
        _listeners.Add(listener);
        return new Subscription(() => _listeners.Remove(listener));
    }

    public void Set(T value)
    {
        CurrentValue = value;
        foreach (var listener in _listeners.ToArray())
            listener(value, Options.DefaultName);
    }

    private sealed class Subscription(Action dispose) : IDisposable
    {
        public void Dispose() => dispose();
    }
}

/// <summary>Store de permissões configurável (inclusive para falhar).</summary>
internal sealed class FakePermissionStore : IPermissionStore
{
    public Func<PermissionContext, IReadOnlyCollection<string>> Resolve { get; set; } = _ => [];

    public int Calls;

    public ValueTask<IReadOnlyCollection<string>> GetPermissionsAsync(PermissionContext context, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        return ValueTask.FromResult(Resolve(context));
    }
}

/// <summary>Provedor de token com contagem de chamadas e validade controlada.</summary>
internal sealed class CountingTokenProvider(TimeProvider clock, TimeSpan lifetime) : CachingAccessTokenProvider("Fake", clock)
{
    private readonly TimeProvider _clock = clock;

    public int Calls;

    protected override ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
    {
        int call = Interlocked.Increment(ref Calls);
        return ValueTask.FromResult(new AccessToken($"token-{call}", _clock.GetUtcNow().Add(lifetime)));
    }
}

/// <summary>Relógio manual.</summary>
internal sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>
/// Cofre falso com um certificado RSA e a "chave do cofre" correspondente: a assinatura acontece aqui dentro, como no Key Vault.
/// </summary>
internal sealed class FakeVaultCertificate : ICertificateReader, IKeyCryptography, IDisposable
{
    public const string Name = "entra-app";
    public const string Version = "0123456789abcdef0123456789abcdef";

    private readonly RSA _rsa = RSA.Create(2048);

    public FakeVaultCertificate()
    {
        var request = new CertificateRequest("CN=tec-security-teste", _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        Cer = certificate.Export(X509ContentType.Cert);
    }

    public byte[] Cer { get; }

    public string ProviderName => "Fake";

    public int SignCalls;

    public RSA PublicKey => _rsa;

    public Task<Result<VaultCertificate>> GetCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        Task.FromResult(Result.Success(new VaultCertificate
        {
            Properties = new CertificateProperties { Name = name, Version = Version },
            Cer = Cer
        }));

    public Task<Result<VaultSignResult>> SignDataAsync(string name, byte[] data, VaultSignatureAlgorithm algorithm, string? version = null,
        CancellationToken cancellationToken = default)
    {
        Interlocked.Increment(ref SignCalls);
        if (name != Name || version != Version || algorithm != VaultSignatureAlgorithm.PS256)
            return Task.FromResult(Result.Failure<VaultSignResult>(Error.NotFound("VAULT_ITEM_NAO_ENCONTRADO", "x")));

        byte[] signature = _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return Task.FromResult(Result.Success(new VaultSignResult(name, Version, algorithm, signature)));
    }

    public Task<Result<X509Certificate2>> DownloadCertificateAsync(string name, string? version = null, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("A chave privada não deve sair do cofre.");

    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificatesAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<Result<IReadOnlyList<CertificateProperties>>> ListCertificateVersionsAsync(string name, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException();

    public Task<Result<VaultEncryptResult>> EncryptAsync(string name, byte[] plaintext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<Result<byte[]>> DecryptAsync(string name, string version, byte[] ciphertext, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<Result<VaultEncryptResult>> WrapKeyAsync(string name, byte[] key, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        string? version = null, CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<Result<byte[]>> UnwrapKeyAsync(string name, string version, byte[] wrappedKey, VaultEncryptionAlgorithm algorithm = VaultEncryptionAlgorithm.RsaOaep256,
        CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public Task<Result<bool>> VerifyDataAsync(string name, string version, byte[] data, byte[] signature, VaultSignatureAlgorithm algorithm,
        CancellationToken cancellationToken = default) => throw new NotSupportedException();

    public void Dispose() => _rsa.Dispose();
}
