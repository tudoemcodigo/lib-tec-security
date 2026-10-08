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
/// <para>Cada versão do cadastro é validada por inteiro antes de entrar em uso: ids fora do formato, id externo vazio ou o
/// mesmo id externo em dois tenants recusam a versão. Na criação (inicialização), a falha lança
/// <see cref="InvalidOperationException"/>; numa recarga, a versão é ignorada com log de erro (evento 3101) e a anterior
/// continua valendo (falha fechada: um appsettings quebrado não libera nem bloqueia tenants por engano).</para>
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
        var snapshot = Build(options, out string? error);
        if (snapshot is null)
        {
            if (_logger is not null)
                SecurityLog.TenantReloadRejected(_logger, error ?? "inválido");
            return;
        }

        _snapshot = snapshot;
        if (_logger is not null)
            SecurityLog.TenantsReloaded(_logger, snapshot.ById.Count);
    }

    private static string Key(string provider, string externalId) =>
        string.Concat(provider.ToUpperInvariant(), "\n", externalId.ToUpperInvariant());

    /// <summary>Valida e monta o snapshot; <c>null</c> com o motivo em <paramref name="error"/> (sem valores sensíveis).</summary>
    internal static Snapshot? Build(TenantOptions options, out string? error)
    {
        // Ids diferem por mais que maiúsculas (recusado abaixo) e são só ASCII: a busca ignora maiúsculas, como a por id externo
        var byId = new Dictionary<string, TenantInfo>(StringComparer.OrdinalIgnoreCase);
        var byExternal = new Dictionary<string, string>(StringComparer.Ordinal);
        var enabledByProvider = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var idsIgnoringCase = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (id, definition) in options.Items)
        {
            if (!SecurityRules.IsValidTenantId(id))
            {
                error = "id de tenant fora do formato (letras, dígitos, '_', '.', '-'; até 64 caracteres).";
                return null;
            }

            if (!idsIgnoringCase.Add(id))
            {
                error = $"o tenant '{id}' aparece mais de uma vez (ids não podem diferir só por maiúsculas).";
                return null;
            }

            if (definition is null)
            {
                error = $"o tenant '{id}' está vazio.";
                return null;
            }

            byId[id] = new TenantInfo(id, SecurityRules.SanitizeDisplayName(definition.Name), definition.Enabled);

            foreach (var (provider, externalIds) in definition.IdentityProviders)
            {
                if (!SecurityRules.IsValidName(provider))
                {
                    error = $"o tenant '{id}' tem um tipo de provedor fora do formato.";
                    return null;
                }

                foreach (string? externalId in externalIds ?? [])
                {
                    if (!SecurityRules.IsValidUserId(externalId))
                    {
                        error = $"o tenant '{id}' tem um id externo vazio ou fora do formato no provedor '{provider}'.";
                        return null;
                    }

                    if (!byExternal.TryAdd(Key(provider, externalId!), id) && byExternal[Key(provider, externalId!)] != id)
                    {
                        error = $"o mesmo id externo do provedor '{provider}' está vinculado a mais de um tenant.";
                        return null;
                    }

                    if (definition.Enabled)
                    {
                        if (!enabledByProvider.TryGetValue(provider, out var set))
                            enabledByProvider[provider] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        set.Add(externalId!);
                    }
                }
            }
        }

        error = null;
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
