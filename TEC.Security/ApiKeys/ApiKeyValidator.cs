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
/// chave desativada, expirada ou sem <see cref="ApiKeyDefinition.ExpiresOn"/>, ou cadastro inválido (log 3111). Uma recarga
/// inválida do cadastro é ignorada (log 3111 uma vez) e a última versão válida continua valendo.</para>
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
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private volatile ApiKeyOptions? _lastValid;
    private int _misconfigured;
    private long _retryAfter;

    /// <summary>Intervalo mínimo entre releituras de uma configuração de API keys inválida.</summary>
    internal static readonly TimeSpan InvalidConfigurationRetry = TimeSpan.FromSeconds(1);

    /// <summary>Cria o validador.</summary>
    /// <param name="options">Cadastro de API keys (com recarga).</param>
    /// <param name="time">Relógio (expiração das chaves); padrão <see cref="TimeProvider.System"/>.</param>
    /// <param name="logger">Log de auditoria (opcional).</param>
    /// <exception cref="ArgumentNullException"><paramref name="options"/> nulo.</exception>
    public ApiKeyValidator(IOptionsMonitor<ApiKeyOptions> options, TimeProvider? time = null, ILogger<ApiKeyValidator>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _time = time ?? TimeProvider.System;
        _logger = (ILogger?)logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
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
    /// Opções atuais. Se a configuração recarregada for inválida, continua valendo a última válida (como no cadastro de tenants),
    /// com um único log por versão inválida; sem nenhuma válida, <c>null</c> (todas as chaves recusadas).
    /// </summary>
    /// <remarks>
    /// Com a configuração inválida, a leitura (que lança <see cref="OptionsValidationException"/>) é refeita no máximo a cada
    /// <see cref="InvalidConfigurationRetry"/>: uma exceção por requisição custaria caro sob carga (amplificação de DoS).
    /// </remarks>
    private ApiKeyOptions? Current()
    {
        long now = _time.GetTimestamp();
        if (Volatile.Read(ref _misconfigured) == 1 && now < Interlocked.Read(ref _retryAfter))
            return _lastValid;

        try
        {
            var options = _options.CurrentValue;
            _lastValid = options;
            Volatile.Write(ref _misconfigured, 0);
            return options;
        }
        catch (OptionsValidationException exception)
        {
            Interlocked.Exchange(ref _retryAfter, now + (long)(InvalidConfigurationRetry.TotalSeconds * _time.TimestampFrequency));
            if (Interlocked.Exchange(ref _misconfigured, 1) == 0)
                SecurityLog.ApiKeyMisconfigured(_logger, "*", exception.Message);
            return _lastValid;
        }
    }

    private ExternalIdentity? Reject(string reason, string keyId, string scheme)
    {
        SecurityLog.ApiKeyRejected(_logger, reason, keyId);
        SecurityDiagnostics.RecordAuthenticationFailure(scheme, "api_key");
        return null;
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

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
