using Microsoft.AspNetCore.Authorization;

namespace TEC.Security.AspNetCore.Authorization;

/// <summary>Requisito de um <see cref="TecAuthorizeAttribute"/>: listas vazias não restringem.</summary>
public sealed class TecRequirement : IAuthorizationRequirement
{
    internal TecRequirement(string[] permissions, string[] roles, string[] scopes, string[] schemes, TecPrincipalKinds kinds)
    {
        Permissions = permissions;
        Roles = roles;
        Scopes = scopes;
        Schemes = schemes;
        Kinds = kinds;
    }

    /// <summary>Permissões aceitas (basta uma).</summary>
    public IReadOnlyList<string> Permissions { get; }

    /// <summary>Papéis aceitos (basta um).</summary>
    public IReadOnlyList<string> Roles { get; }

    /// <summary>Escopos aceitos (basta um).</summary>
    public IReadOnlyList<string> Scopes { get; }

    /// <summary>Esquemas aceitos.</summary>
    public IReadOnlyList<string> Schemes { get; }

    /// <summary>Tipos de identidade aceitos.</summary>
    public TecPrincipalKinds Kinds { get; }

    /// <inheritdoc />
    public override string ToString() =>
        $"TecRequirement(Permissions=[{string.Join(',', Permissions)}], Roles=[{string.Join(',', Roles)}], Scopes=[{string.Join(',', Scopes)}], " +
        $"Schemes=[{string.Join(',', Schemes)}], Kinds={Kinds})";
}

/// <summary>
/// Requisito da DefaultPolicy e da FallbackPolicy: identidade autenticada <b>e</b> normalizada pelo TEC.Security. Uma
/// identidade de outro mecanismo de autenticação (sem a normalização) é negada.
/// </summary>
public sealed class TecAuthenticatedRequirement : IAuthorizationRequirement
{
    /// <summary>Instância única.</summary>
    public static readonly TecAuthenticatedRequirement Instance = new();

    private TecAuthenticatedRequirement()
    {
    }
}
