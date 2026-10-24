using System.Collections.Frozen;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Security.Abstractions;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Internal;

namespace TEC.Security.Tenants;

/// <summary>
/// Cadastro de tenants lido de <see cref="TenantOptions"/> (seção <c>Security:Tenants</c>), com recarga sem reinício.
/// </summary>
/// <remarks>
/// <para>Cada versão do cadastro é validada por inteiro: ids fora do formato, id externo vazio ou o mesmo id externo em dois
/// tenants tornam a versão inválida. Na criação (inicialização), a falha lança <see cref="InvalidOperationException"/>.</para>
/// <para>Numa recarga com erro, a versão nova vale <b>por entrada</b>, com log de erro (evento 3101): os tenants válidos dela
/// entram em uso, inclusive desativações e remoções, e só as entradas com erro falham fechadas (tenant com id fora do
/// formato, vazio ou repetido com outra grafia sai do cadastro; tenant com provedor ou id externo fora do formato fica
/// inativo; id externo vinculado a mais de um tenant deixa de ser resolvido). Assim um erro de edição em outra entrada nunca
/// mantém ativo um tenant que a mesma edição desativou, e nunca ativa uma entrada com erro.</para>
/// <para>Consultas são leituras de um snapshot imutável (thread-safe, sem bloqueio).</para>
/// </remarks>
public sealed class ConfigurationTenantRegistry : ITenantRegistry, IDisposable
{
    private readonly ILogger? _logger;
    private readonly IDisposable? _subscription;
    private volatile Snapshot _snapshot;

    /// <summary>Cria o cadastro e passa a acompanhar as recargas de <paramref name="options"/>.</summary>
    /// <exception cref="InvalidOperationException">Cadastro inicial inválido.</exception>
    public ConfigurationTenantRegistry(IOptionsMonitor<TenantOptions> options, ILogger<ConfigurationTenantRegistry>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _logger = logger;

        var initial = Build(options.CurrentValue, out string? error);
        _snapshot = initial ?? throw new InvalidOperationException($"Cadastro de tenants ({TenantOptions.SectionName}) inválido: {error}");
        _subscription = options.OnChange(Reload);
    }

    /// <inheritdoc />
    public TenantInfo? FindByExternalId(string provider, string externalTenantId)
    {
        // Mesmo formato exigido no cadastro (só ASCII): a chave usa ToUpperInvariant, que fora do ASCII junta letras diferentes
        // (ex.: 'ſ' vira 'S'), e um id externo forjado resolveria para o tenant de outro id
        if (!SecurityRules.IsValidName(provider) || !SecurityRules.IsValidUserId(externalTenantId))
            return null;

        var snapshot = _snapshot;
        return snapshot.ByExternalId.TryGetValue(Key(provider, externalTenantId), out var tenantId)
            ? snapshot.ById[tenantId]
            : null;
    }

    /// <inheritdoc />
    public TenantInfo? Find(string tenantId) =>
        !string.IsNullOrEmpty(tenantId) && _snapshot.ById.TryGetValue(tenantId, out var tenant) ? tenant : null;

    /// <inheritdoc />
    public IReadOnlySet<string> GetEnabledExternalIds(string provider) =>
        _snapshot.EnabledExternalIds.TryGetValue(provider ?? string.Empty, out var ids) ? ids : FrozenSet<string>.Empty;

    /// <inheritdoc />
    public void Dispose() => _subscription?.Dispose();

    private void Reload(TenantOptions options)
    {
        // Recarga: a versão nova nunca é recusada por inteiro (isso manteria ativos tenants que ela desativou ou removeu);
        // as entradas com erro falham fechadas e as demais valem
        var snapshot = Build(options, strict: false, out string? error)!;
        _snapshot = snapshot;
        if (_logger is null)
            return;

        if (error is not null)
            SecurityLog.TenantReloadRejected(_logger, error);
        else
            SecurityLog.TenantsReloaded(_logger, snapshot.ById.Count);
    }

    private static string Key(string provider, string externalId) =>
        string.Concat(provider.ToUpperInvariant(), "\n", externalId.ToUpperInvariant());

    /// <summary>Valida e monta o snapshot; <c>null</c> com o motivo em <paramref name="error"/> (sem valores sensíveis).</summary>
    internal static Snapshot? Build(TenantOptions options, out string? error) => Build(options, strict: true, out error);

    /// <summary>
    /// Valida e monta o snapshot. Com <paramref name="strict"/>, qualquer erro recusa a versão (<c>null</c>, com o primeiro
    /// erro em <paramref name="error"/>). Sem ele (recarga), o snapshot é sempre montado: as entradas com erro falham fechadas
    /// (ver a classe) e <paramref name="error"/> lista os problemas. As mensagens não trazem valores sensíveis.
    /// </summary>
    internal static Snapshot? Build(TenantOptions options, bool strict, out string? error)
    {
        // Ids diferem por mais que maiúsculas (recusado abaixo) e são só ASCII: a busca ignora maiúsculas, como a por id externo
        var byId = new Dictionary<string, TenantInfo>(StringComparer.OrdinalIgnoreCase);
        var byExternal = new Dictionary<string, string>(StringComparer.Ordinal);
        var enabledByProvider = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var errors = new List<string>();

        // Grafias repetidas do mesmo id e ids externos vinculados a mais de um tenant: ambíguos, nenhuma das entradas vale
        var repeatedIds = options.Items.Keys.GroupBy(id => id, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1).Select(g => g.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var owners = new Dictionary<string, string>(StringComparer.Ordinal);
        var ambiguous = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, definition) in options.Items)
        {
            if (definition is null || !SecurityRules.IsValidTenantId(id))
                continue;
            foreach (var (provider, externalIds) in definition.IdentityProviders)
            {
                if (!SecurityRules.IsValidName(provider))
                    continue;
                foreach (string? externalId in externalIds ?? [])
                {
                    if (SecurityRules.IsValidUserId(externalId) && !owners.TryAdd(Key(provider, externalId!), id)
                        && !owners[Key(provider, externalId!)].Equals(id, StringComparison.OrdinalIgnoreCase))
                        ambiguous.Add(Key(provider, externalId!));
                }
            }
        }

        foreach (var (id, definition) in options.Items)
        {
            if (!SecurityRules.IsValidTenantId(id))
            {
                errors.Add("id de tenant fora do formato (letras, dígitos, '_', '.', '-'; até 64 caracteres).");
                continue;
            }

            if (repeatedIds.Contains(id))
            {
                errors.Add($"o tenant '{id}' aparece mais de uma vez (ids não podem diferir só por maiúsculas).");
                continue;
            }

            if (definition is null)
            {
                errors.Add($"o tenant '{id}' está vazio.");
                continue;
            }

            // Provedor ou id externo fora do formato: a entrada é suspeita e o tenant fica inativo
            string? linkError = null;
            foreach (var (provider, externalIds) in definition.IdentityProviders)
            {
                if (!SecurityRules.IsValidName(provider))
                    linkError ??= $"o tenant '{id}' tem um tipo de provedor fora do formato.";
                else if ((externalIds ?? []).Any(e => !SecurityRules.IsValidUserId(e)))
                    linkError ??= $"o tenant '{id}' tem um id externo vazio ou fora do formato no provedor '{provider}'.";
            }

            if (linkError is not null)
                errors.Add(linkError);

            bool enabled = definition.Enabled && linkError is null;
            byId[id] = new TenantInfo(id, SecurityRules.SanitizeDisplayName(definition.Name), enabled);

            foreach (var (provider, externalIds) in definition.IdentityProviders)
            {
                if (!SecurityRules.IsValidName(provider))
                    continue;

                foreach (string? externalId in externalIds ?? [])
                {
                    if (!SecurityRules.IsValidUserId(externalId))
                        continue;

                    string key = Key(provider, externalId!);
                    if (ambiguous.Contains(key))
                    {
                        errors.Add($"o mesmo id externo do provedor '{provider}' está vinculado a mais de um tenant.");
                        continue;
                    }

                    byExternal.TryAdd(key, id);
                    if (enabled)
                    {
                        if (!enabledByProvider.TryGetValue(provider, out var set))
                            enabledByProvider[provider] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        set.Add(externalId!);
                    }
                }
            }
        }

        if (errors.Count == 0)
            error = null;
        else if (strict)
        {
            error = errors[0];
            return null;
        }
        else
        {
            error = "entradas com erro falharam fechadas, as demais da versão nova valem: " + string.Join(" ", errors.Distinct(StringComparer.Ordinal));
        }

        return new Snapshot(
            byId.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
            byExternal.ToFrozenDictionary(StringComparer.Ordinal),
            enabledByProvider.ToFrozenDictionary(p => p.Key, p => (IReadOnlySet<string>)p.Value.ToFrozenSet(StringComparer.OrdinalIgnoreCase),
                StringComparer.OrdinalIgnoreCase));
    }

    internal sealed record Snapshot(
        FrozenDictionary<string, TenantInfo> ById,
        FrozenDictionary<string, string> ByExternalId,
        FrozenDictionary<string, IReadOnlySet<string>> EnabledExternalIds);
}
