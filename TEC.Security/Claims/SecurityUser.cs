using System.Collections.Frozen;
using System.Security.Claims;
using TEC.Core.Security;
using TEC.Security.Abstractions;

namespace TEC.Security.Claims;

/// <summary>
/// <see cref="ISecurityUser"/> lido de um <see cref="ClaimsPrincipal"/> normalizado. Sem a marca de normalização
/// (<see cref="TecClaimTypes.Normalized"/>) ou sem id, a identidade é anônima.
/// </summary>
/// <remarks>Os valores são lidos uma vez, na criação: crie uma instância por principal.</remarks>
public sealed class SecurityUser : ISecurityUser
{
    /// <summary>Usuário anônimo.</summary>
    public static readonly SecurityUser Anonymous = new(null);

    /// <summary>Lê os claims normalizados de <paramref name="principal"/>.</summary>
    public SecurityUser(ClaimsPrincipal? principal)
    {
        var identity = FindNormalizedIdentity(principal);
        if (identity is null)
        {
            Roles = Scopes = Permissions = FrozenSet<string>.Empty;
            return;
        }

        string? id = identity.FindFirst(TecClaimTypes.UserId)?.Value;
        if (string.IsNullOrEmpty(id) || !Enum.TryParse<PrincipalKind>(identity.FindFirst(TecClaimTypes.Kind)?.Value, out var kind)
            || kind == PrincipalKind.Anonymous || !Enum.IsDefined(kind))
        {
            Roles = Scopes = Permissions = FrozenSet<string>.Empty;
            return;
        }

        Principal = principal;
        Id = id;
        Kind = kind;
        TenantId = identity.FindFirst(TecClaimTypes.TenantId)?.Value;
        ExternalTenantId = identity.FindFirst(TecClaimTypes.ExternalTenantId)?.Value;
        Name = identity.FindFirst(TecClaimTypes.Name)?.Value;
        Scheme = identity.FindFirst(TecClaimTypes.Scheme)?.Value;
        Provider = identity.FindFirst(TecClaimTypes.Provider)?.Value;
        ClientId = identity.FindFirst(TecClaimTypes.ClientId)?.Value;
        Roles = Values(identity, TecClaimTypes.Role);
        Scopes = Values(identity, TecClaimTypes.Scope);
        Permissions = Values(identity, TecClaimTypes.Permission);
    }

    /// <inheritdoc />
    public bool IsAuthenticated => Id is not null;

    /// <inheritdoc />
    public PrincipalKind Kind { get; }

    /// <inheritdoc />
    public string? Id { get; }

    /// <inheritdoc />
    public string? TenantId { get; }

    /// <inheritdoc />
    public string? Name { get; }

    /// <inheritdoc />
    public string? Scheme { get; }

    /// <inheritdoc />
    public string? Provider { get; }

    /// <inheritdoc />
    public string? ExternalTenantId { get; }

    /// <inheritdoc />
    public string? ClientId { get; }

    /// <inheritdoc />
    public IReadOnlySet<string> Roles { get; }

    /// <inheritdoc />
    public IReadOnlySet<string> Scopes { get; }

    /// <inheritdoc />
    public IReadOnlySet<string> Permissions { get; }

    /// <inheritdoc />
    public ClaimsPrincipal? Principal { get; }

    /// <inheritdoc />
    public bool IsInRole(string role) => role is not null && Roles.Contains(role);

    /// <inheritdoc />
    public bool HasScope(string scope) => scope is not null && Scopes.Contains(scope);

    /// <inheritdoc />
    public bool HasPermission(string permission) => permission is not null && Permissions.Contains(permission);

    /// <inheritdoc />
    public override string ToString() => IsAuthenticated ? $"SecurityUser {{ Kind = {Kind}, Id = {Id}, TenantId = {TenantId} }}" : "SecurityUser { Anonymous }";

    /// <summary>
    /// A identidade autenticada e normalizada pelo TEC.Security, ou <c>null</c>. Uma identidade com a marca mas criada por outro
    /// código seria aceita; por isso a marca só é confiável porque os claims <c>tec_*</c> de qualquer provedor são descartados.
    /// </summary>
    internal static ClaimsIdentity? FindNormalizedIdentity(ClaimsPrincipal? principal)
    {
        if (principal is null)
            return null;

        foreach (var identity in principal.Identities)
        {
            if (identity.IsAuthenticated && identity.HasClaim(TecClaimTypes.Normalized, TecClaimTypes.NormalizedValue))
                return identity;
        }

        return null;
    }

    private static FrozenSet<string> Values(ClaimsIdentity identity, string type) =>
        identity.FindAll(type).Select(c => c.Value).ToFrozenSet(StringComparer.Ordinal);
}
