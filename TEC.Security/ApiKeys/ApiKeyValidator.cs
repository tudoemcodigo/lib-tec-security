using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Core.Security;
using TEC.Core.Text.Codecs;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Diagnostics;
using TEC.Security.Internal;

namespace TEC.Security.ApiKeys;

/// <summary>
/// Valida uma API key apresentada contra o cadastro (<see cref="ApiKeyOptions"/>) e devolve a identidade de aplicação
/// correspondente. Singleton, usado pelo esquema de autenticação de API key do <c>TEC.Security.AspNetCore</c>.
/// </summary>
/// <remarks>
/// <para>Recusada (com log de auditoria 3110 com o id, nunca o segredo): formato inválido, id desconhecido, hash diferente,
/// chave desativada, expirada ou sem <see cref="ApiKeyDefinition.ExpiresOn"/>, ou cadastro inválido (log 3111).</para>
/// <para>Uma recarga com erro (log 3111 uma vez) vale <b>por chave</b>: as chaves válidas da versão nova entram em uso,
/// inclusive desativações e remoções, e as chaves com erro ficam recusadas (falha fechada). Um erro de edição numa chave nunca
/// mantém ativa outra chave que a mesma edição revogou. Um <c>HeaderName</c> inválido mantém o da última versão válida.
/// Sem como ler a versão nova sem validação (validador criado fora do <c>AddTecSecurity</c>), todas as chaves ficam recusadas
/// até a configuração ser corrigida.</para>
/// <para>Recusas iguais (mesmo id e motivo) geram no máximo um log 3110 por <see cref="RejectionLogInterval"/>, com a
/// contagem das omitidas; a métrica <c>security.authentication.failures</c> conta todas.</para>
/// <para>O hash é sempre calculado e comparado em tempo constante, inclusive para id desconhecido: o tempo de resposta não
/// revela quais ids existem.</para>
/// </remarks>
public sealed class ApiKeyValidator
{
    /// <summary>Esquema e provedor das identidades de API key.</summary>
    public const string ProviderName = "ApiKey";

    private static readonly byte[] DummyHash = SHA256.HashData("tec-api-key-inexistente"u8);

    // O mesmo hash fictício em Base64Url: id desconhecido também passa pela decodificação do hash cadastrado (mesmo custo)
    private static readonly string DummyHashText = Base64UrlEncoder.Encode(DummyHash);

    private readonly IOptionsMonitor<ApiKeyOptions> _options;
    private readonly Func<ApiKeyOptions>? _readUnvalidated;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly RejectionLogLimiter _rejectionLog;
    private volatile ApiKeyOptions? _lastValid;
    private volatile ApiKeyOptions? _effective;
    private int _misconfigured;
    private long _retryAfter;

    /// <summary>Intervalo mínimo entre releituras de uma configuração de API keys inválida.</summary>
    internal static readonly TimeSpan InvalidConfigurationRetry = TimeSpan.FromSeconds(1);

    /// <summary>Intervalo mínimo entre dois logs 3110 com o mesmo id e motivo.</summary>
    public static readonly TimeSpan RejectionLogInterval = TimeSpan.FromMinutes(1);

    /// <summary>Cria o validador.</summary>
    /// <param name="options">Cadastro de API keys (com recarga).</param>
    /// <param name="time">Relógio (expiração das chaves); padrão <see cref="TimeProvider.System"/>.</param>
    /// <param name="logger">Log de auditoria (opcional).</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> nulo.</exception>
    public ApiKeyValidator(IOptionsMonitor<ApiKeyOptions> options, TimeProvider? time = null, ILogger<ApiKeyValidator>? logger = null)
        : this(options, time, logger, readUnvalidated: null)
    {
    }

    /// <summary>Cria o validador com a leitura do cadastro sem validação (usada para aplicar por chave uma recarga com erro).</summary>
    internal ApiKeyValidator(IOptionsMonitor<ApiKeyOptions> options, TimeProvider? time, ILogger<ApiKeyValidator>? logger,
        Func<ApiKeyOptions>? readUnvalidated)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _readUnvalidated = readUnvalidated;
        _time = time ?? TimeProvider.System;
        _logger = (ILogger?)logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
        _rejectionLog = new RejectionLogLimiter(_time, RejectionLogInterval);
    }

    /// <summary>Header configurado.</summary>
    public string HeaderName => Current()?.HeaderName ?? "X-Api-Key";

    /// <summary>
    /// Identidade da chave (para o <see cref="SecurityIdentityFactory"/>), ou <c>null</c> se recusada.
    /// </summary>
    /// <param name="presented">Valor recebido no header.</param>
    /// <param name="scheme">Nome do esquema de autenticação.</param>
    /// <returns>A identidade de aplicação da chave, ou <c>null</c> (recusada; o motivo vai só para o log).</returns>
    public ExternalIdentity? Validate(string? presented, string scheme = ProviderName)
    {
        if (!ApiKeyGenerator.TryParse(presented, out string keyId, out string secret))
            return Reject("formato inválido", "?", scheme);

        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        byte[] presentedHash = SHA256.HashData(secretBytes);
        CryptographicOperations.ZeroMemory(secretBytes);   // o segredo apresentado não fica em memória além do hash
        var options = Current();
        ApiKeyDefinition? definition = null;
        if (options is not null && options.Keys.TryGetValue(keyId, out var found))
            definition = found;

        byte[]? expected = ApiKeyGenerator.DecodeHash(definition is null ? DummyHashText : definition.Hash);
        bool matches = CryptographicOperations.FixedTimeEquals(presentedHash, expected ?? DummyHash);

        if (definition is null)
            return Reject("id desconhecido", keyId, scheme);

        if (expected is null)
        {
            SecurityLog.ApiKeyMisconfigured(_logger, keyId, "Hash ausente ou fora do formato (SHA-256 em Base64Url).");
            return Reject("cadastro inválido", keyId, scheme);
        }

        if (!matches)
            return Reject("segredo incorreto", keyId, scheme);

        if (!definition.Enabled)
            return Reject("chave desativada", keyId, scheme);

        if (definition.ExpiresOn is not { } expiresOn)
        {
            SecurityLog.ApiKeyMisconfigured(_logger, keyId, "ExpiresOn é obrigatório.");
            return Reject("cadastro inválido", keyId, scheme);
        }

        if (expiresOn <= _time.GetUtcNow())
            return Reject("chave expirada", keyId, scheme);

        return new ExternalIdentity
        {
            Scheme = scheme,
            Provider = ProviderName,
            UserId = "apikey:" + keyId,
            Kind = PrincipalKind.Application,
            TenantId = string.IsNullOrWhiteSpace(definition.TenantId) ? null : definition.TenantId,
            Name = definition.Name ?? keyId,
            ClientId = keyId,
            Roles = [.. definition.Roles],
            Permissions = [.. definition.Permissions]
        };
    }

    /// <summary>
    /// Opções atuais. Se a configuração recarregada for inválida, vale a versão nova só com as chaves válidas (como no cadastro
    /// de tenants), com um único log por versão inválida; sem como lê-la, <c>null</c> (todas as chaves recusadas).
    /// </summary>
    /// <remarks>
    /// Com a configuração inválida, a leitura (que lança <see cref="OptionsValidationException"/>) é refeita no máximo a cada
    /// <see cref="InvalidConfigurationRetry"/>: uma exceção por requisição custaria caro sob carga (amplificação de DoS).
    /// </remarks>
    private ApiKeyOptions? Current()
    {
        long now = _time.GetTimestamp();
        if (Volatile.Read(ref _misconfigured) == 1 && now < Interlocked.Read(ref _retryAfter))
            return _effective;

        try
        {
            var options = _options.CurrentValue;
            _lastValid = options;
            _effective = options;
            Volatile.Write(ref _misconfigured, 0);
            return options;
        }
        catch (OptionsValidationException exception)
        {
            var effective = ValidKeysOnly();
            _effective = effective;
            Interlocked.Exchange(ref _retryAfter, now + (long)(InvalidConfigurationRetry.TotalSeconds * _time.TimestampFrequency));
            if (Interlocked.Exchange(ref _misconfigured, 1) == 0)
            {
                SecurityLog.ApiKeyMisconfigured(_logger, "*", effective is null
                    ? "cadastro recarregado com erro; todas as chaves recusadas até a correção. " + exception.Message
                    : "cadastro recarregado com erro; as chaves com erro ficam recusadas e as demais da versão nova valem. " + exception.Message);
            }

            return effective;
        }
    }

    /// <summary>
    /// Versão nova (lida sem validação) só com as chaves que passam na validação; o header inválido é trocado pelo da última
    /// versão válida. <c>null</c> se não houver como lê-la (todas as chaves recusadas).
    /// </summary>
    private ApiKeyOptions? ValidKeysOnly()
    {
        ApiKeyOptions? candidate;
        try
        {
            candidate = _readUnvalidated?.Invoke();
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException)
        {
            candidate = null;   // valor que nem converte (ex.: data inválida): nada da versão nova é confiável
        }

        if (candidate is null)
            return null;

        var effective = new ApiKeyOptions
        {
            HeaderName = ApiKeyOptionsValidator.IsValidHeaderName(candidate.HeaderName)
                ? candidate.HeaderName
                : _lastValid?.HeaderName ?? new ApiKeyOptions().HeaderName
        };

        var failures = new List<string>();
        foreach (var (id, key) in candidate.Keys)
        {
            failures.Clear();
            ApiKeyOptionsValidator.ValidateKey(id, key, failures);
            if (failures.Count == 0)
                effective.Keys[id] = key;
        }

        return effective;
    }

    private ExternalIdentity? Reject(string reason, string keyId, string scheme)
    {
        if (_rejectionLog.TryEnter(keyId, reason, out int suppressed))
            SecurityLog.ApiKeyRejected(_logger, reason, keyId, suppressed);
        SecurityDiagnostics.RecordAuthenticationFailure(scheme, "api_key");
        return null;
    }
}

/// <summary>
/// Limita os logs de recusa repetidos (mesmo id e motivo) a um por intervalo, contando os omitidos. Memória limitada: com
/// muitos ids distintos (ids inventados por um atacante), os novos dividem uma única entrada.
/// </summary>
internal sealed class RejectionLogLimiter(TimeProvider time, TimeSpan interval, int maxEntries = 1024)
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(string KeyId, string Reason), Window> _windows = new();

    /// <summary><c>true</c> se o log deve ser feito agora; <paramref name="suppressed"/> = recusas iguais omitidas antes dele.</summary>
    public bool TryEnter(string keyId, string reason, out int suppressed)
    {
        var now = time.GetUtcNow();
        var key = (keyId, reason);
        if (!_windows.ContainsKey(key) && _windows.Count >= maxEntries)
        {
            foreach (var (existing, window) in _windows)
            {
                if (now - window.Start >= interval)
                    _windows.TryRemove(existing, out _);
            }

            if (_windows.Count >= maxEntries)
                key = ("*", reason);
        }

        var current = _windows.GetOrAdd(key, static (_, start) => new Window(start), now - interval);
        lock (current)
        {
            if (now - current.Start >= interval)
            {
                suppressed = current.Suppressed;
                current.Start = now;
                current.Suppressed = 0;
                return true;
            }

            current.Suppressed++;
            suppressed = 0;
            return false;
        }
    }

    private sealed class Window(DateTimeOffset start)
    {
        public DateTimeOffset Start = start;

        public int Suppressed;
    }
}

/// <summary>Validação do cadastro de API keys na inicialização (<c>ValidateOnStart</c>) e a cada recarga.</summary>
internal sealed class ApiKeyOptionsValidator : IValidateOptions<ApiKeyOptions>
{
    public ValidateOptionsResult Validate(string? name, ApiKeyOptions options)
    {
        var failures = new List<string>();

        if (string.IsNullOrWhiteSpace(options.HeaderName) || options.HeaderName.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            failures.Add("ApiKeys:HeaderName inválido (letras, dígitos e hífen).");
        else if (options.HeaderName.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
            failures.Add("ApiKeys:HeaderName não pode ser 'Authorization' (reservado para tokens bearer).");

        foreach (var (id, key) in options.Keys)
            ValidateKey(id, key, failures);

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    /// <summary>Header válido (as mesmas regras de <see cref="Validate"/>).</summary>
    internal static bool IsValidHeaderName(string? headerName) =>
        !string.IsNullOrWhiteSpace(headerName) && headerName.All(c => char.IsAsciiLetterOrDigit(c) || c == '-')
        && !headerName.Equals("Authorization", StringComparison.OrdinalIgnoreCase);

    /// <summary>Valida uma chave do cadastro, acrescentando os problemas em <paramref name="failures"/>.</summary>
    internal static void ValidateKey(string id, ApiKeyDefinition? key, List<string> failures)
    {
        if (!SecurityRules.IsValidServiceName(id))
            failures.Add("ApiKeys:Keys: id fora do formato (minúsculas, dígitos e hífen, 3 a 40 caracteres).");
        else if (key is null)
            failures.Add($"ApiKeys:Keys:{id} está vazio.");
        else
        {
            if (ApiKeyGenerator.DecodeHash(key.Hash) is null)
                failures.Add($"ApiKeys:Keys:{id}:Hash ausente ou fora do formato (use ApiKeyGenerator.Generate).");
            if (key.ExpiresOn is null)
                failures.Add($"ApiKeys:Keys:{id}:ExpiresOn é obrigatório.");
            if (key.TenantId is not null && !SecurityRules.IsValidTenantId(key.TenantId))
                failures.Add($"ApiKeys:Keys:{id}:TenantId fora do formato.");
            if (key.Roles.Concat(key.Permissions).Any(v => !SecurityRules.IsValidName(v)))
                failures.Add($"ApiKeys:Keys:{id}: papel ou permissão fora do formato.");
        }
    }
}
