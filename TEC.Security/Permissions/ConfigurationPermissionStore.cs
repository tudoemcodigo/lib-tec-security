using Microsoft.Extensions.Options;
using TEC.Security.Abstractions;
using TEC.Security.Configuration;

namespace TEC.Security.Permissions;

/// <summary>
/// <see cref="IPermissionStore"/> padrão: mapeamento papel → permissões de <see cref="PermissionOptions"/>
/// (<c>Security:Permissions:Roles</c>, para todos os tenants, mais <c>Security:Permissions:Tenants:{tenant}:Roles</c>, só para o
/// tenant da identidade), com recarga. Papéis sem mapeamento não geram permissões.
/// </summary>
public sealed class ConfigurationPermissionStore(IOptionsMonitor<PermissionOptions> options) : IPermissionStore
{
    /// <inheritdoc />
    public ValueTask<IReadOnlyCollection<string>> GetPermissionsAsync(PermissionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var current = options.CurrentValue;
        var permissions = new HashSet<string>(StringComparer.Ordinal);
        Add(permissions, current.Roles, context.Roles);

        if (context.TenantId is { } tenantId && current.Tenants.TryGetValue(tenantId, out var tenant) && tenant is not null)
            Add(permissions, tenant.Roles, context.Roles);

        return ValueTask.FromResult<IReadOnlyCollection<string>>(permissions);
    }

    private static void Add(HashSet<string> permissions, Dictionary<string, List<string>> map, IReadOnlyCollection<string> roles)
    {
        if (map.Count == 0)
            return;

        foreach (string role in roles)
        {
            if (map.TryGetValue(role, out var granted) && granted is not null)
                permissions.UnionWith(granted.Where(p => p is not null));
        }
    }
}
