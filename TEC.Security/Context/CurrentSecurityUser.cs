using System.Security.Claims;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.Claims;

namespace TEC.Security.Context;

/// <summary>
/// <see cref="ISecurityUser"/>/<see cref="ICurrentUser"/>/<see cref="ICurrentTenant"/> registrados no container: a cada acesso
/// leem o principal atual da <see cref="IPrincipalSource"/>. Assim, um mesmo escopo de DI acompanha as trocas de identidade
/// feitas com <see cref="ISecurityContext.RunAs"/> (ex.: worker que processa mensagens de usuários diferentes).
/// </summary>
internal sealed class CurrentSecurityUser(IPrincipalSource source, ITenantRegistry tenants) : ISecurityUser, ICurrentTenant
{
    // Par (principal, usuário) numa única referência imutável: fluxos paralelos no mesmo escopo (RunAs com identidades
    // diferentes) leem e trocam o cache de forma atômica, sem misturar o principal de um com o usuário do outro
    private volatile Cached? _cache;

    private SecurityUser User
    {
        get
        {
            var principal = source.Principal;
            if (principal is null)
                return SecurityUser.Anonymous;

            var cache = _cache;
            if (cache is not null && ReferenceEquals(cache.Principal, principal))
                return cache.User;

            var user = new SecurityUser(principal);
            _cache = new Cached(principal, user);
            return user;
        }
    }

    private sealed record Cached(ClaimsPrincipal Principal, SecurityUser User);

    public bool IsAuthenticated => User.IsAuthenticated;

    public PrincipalKind Kind => User.Kind;

    public string? Id => User.Id;

    public string? TenantId => User.TenantId;

    public string? Name => User.Name;

    public string? Scheme => User.Scheme;

    public string? Provider => User.Provider;

    public string? ExternalTenantId => User.ExternalTenantId;

    public string? ClientId => User.ClientId;

    public IReadOnlySet<string> Roles => User.Roles;

    public IReadOnlySet<string> Scopes => User.Scopes;

    public IReadOnlySet<string> Permissions => User.Permissions;

    public ClaimsPrincipal? Principal => User.Principal;

    public bool IsInRole(string role) => User.IsInRole(role);

    public bool HasScope(string scope) => User.HasScope(scope);

    public bool HasPermission(string permission) => User.HasPermission(permission);

    string? ICurrentTenant.Id => User.TenantId;

    TenantInfo? ICurrentTenant.Info => User.TenantId is { } id ? tenants.Find(id) : null;

    public override string ToString() => User.ToString();
}
