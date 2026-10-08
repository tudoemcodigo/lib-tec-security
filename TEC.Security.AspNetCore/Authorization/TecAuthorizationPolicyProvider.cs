using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using TEC.Security.Common;

namespace TEC.Security.AspNetCore.Authorization;

/// <summary>
/// Nome de policy que carrega a regra de um <see cref="TecAuthorizeAttribute"/>: <c>TEC|p=a,b|r=|s=|h=|k=3</c>. Os valores aceitos
/// (<see cref="SecurityRules.IsValidName"/>) nunca contêm <c>|</c>, <c>=</c> ou <c>,</c>, então a codificação não é ambígua.
/// </summary>
internal static class TecPolicyName
{
    public const string Prefix = "TEC|";

    public static string Encode(TecRequirement requirement) =>
        $"{Prefix}p={string.Join(',', requirement.Permissions)}|r={string.Join(',', requirement.Roles)}" +
        $"|s={string.Join(',', requirement.Scopes)}|h={string.Join(',', requirement.Schemes)}|k={(int)requirement.Kinds}";

    /// <summary>Requisito do nome, ou <c>null</c> se o nome não é do TEC.Security ou está malformado.</summary>
    public static TecRequirement? Decode(string? name)
    {
        if (name is null || !name.StartsWith(Prefix, StringComparison.Ordinal))
            return null;

        var parts = name[Prefix.Length..].Split('|');
        if (parts.Length != 5 || !parts[4].StartsWith("k=", StringComparison.Ordinal) || !int.TryParse(parts[4].AsSpan(2), out int kinds))
            return null;

        string[]? Values(string part, string key)
        {
            if (!part.StartsWith(key + "=", StringComparison.Ordinal))
                return null;
            string[] values = part[(key.Length + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries);
            return values.All(SecurityRules.IsValidName) ? values : null;
        }

        var permissions = Values(parts[0], "p");
        var roles = Values(parts[1], "r");
        var scopes = Values(parts[2], "s");
        var schemes = Values(parts[3], "h");
        var kind = (TecPrincipalKinds)kinds;
        if (permissions is null || roles is null || scopes is null || schemes is null
            || (kind & TecPrincipalKinds.Any) == 0 || (kind & ~TecPrincipalKinds.Any) != 0)
            return null;

        return new TecRequirement(permissions, roles, scopes, schemes, kind);
    }
}

/// <summary>
/// Resolve as policies <c>TEC|...</c> geradas por <see cref="TecAuthorizeAttribute"/> (identidade normalizada + requisito) e
/// delega as demais ao provedor padrão do ASP.NET Core. Um nome <c>TEC|</c> malformado lança exceção (falha fechada).
/// </summary>
internal sealed class TecAuthorizationPolicyProvider(IOptions<AuthorizationOptions> options) : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _default = new(options);
    private readonly ConcurrentDictionary<string, AuthorizationPolicy> _cache = new(StringComparer.Ordinal);

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (!policyName.StartsWith(TecPolicyName.Prefix, StringComparison.Ordinal))
            return _default.GetPolicyAsync(policyName);

        if (_cache.TryGetValue(policyName, out var cached))
            return Task.FromResult<AuthorizationPolicy?>(cached);

        var requirement = TecPolicyName.Decode(policyName)
                          ?? throw new InvalidOperationException("Policy do TEC.Security malformada.");
        var policy = new AuthorizationPolicyBuilder()
            .AddRequirements(TecAuthenticatedRequirement.Instance, requirement)
            .Build();

        // Limite: nomes vêm de atributos do código (conjunto finito); o limite só evita crescimento por nomes inesperados
        if (_cache.Count < 10_000)
            _cache.TryAdd(policyName, policy);
        return Task.FromResult<AuthorizationPolicy?>(policy);
    }

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _default.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _default.GetFallbackPolicyAsync();
}
