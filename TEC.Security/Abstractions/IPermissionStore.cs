using TEC.Core.Security;

namespace TEC.Security.Abstractions;

/// <summary>Dados da identidade usados para descobrir as permissões.</summary>
/// <param name="Provider">Tipo do provedor (ex.: <c>EntraId</c>).</param>
/// <param name="Scheme">Esquema de autenticação.</param>
/// <param name="UserId">Identificador estável da identidade.</param>
/// <param name="TenantId">Tenant da aplicação (ou <c>null</c>).</param>
/// <param name="Kind">Tipo da identidade.</param>
/// <param name="Roles">Papéis normalizados vindos do provedor.</param>
public sealed record PermissionContext(
    string Provider,
    string Scheme,
    string UserId,
    string? TenantId,
    PrincipalKind Kind,
    IReadOnlyCollection<string> Roles);

/// <summary>
/// Fonte das permissões de uma identidade (modelo "papéis do token → permissões da aplicação"). Consultado uma vez por
/// autenticação; o resultado vira claims <c>tec_perm</c>.
/// </summary>
/// <remarks>
/// <para>Padrão: <see cref="Permissions.ConfigurationPermissionStore"/>, que lê o mapeamento papel → permissões de
/// <c>Security:Permissions:Roles</c> (com recarga). Para buscar do banco (ex.: TEC.ORM), implemente esta interface e registre
/// com <c>security.UsePermissionStore&lt;T&gt;()</c>, que adiciona cache (padrão: 5 minutos).</para>
/// <para>Falha fechada: uma exceção do store faz a autenticação falhar (HTTP 401), nunca autoriza sem permissões conhecidas.
/// Permissões fora do formato (<see cref="Common.SecurityRules.IsValidName"/>) são descartadas com log de aviso.</para>
/// </remarks>
/// <example>
/// <code>
/// internal sealed class PermissoesDoBanco(IPerfilRepository perfis) : IPermissionStore
/// {
///     public async ValueTask&lt;IReadOnlyCollection&lt;string&gt;&gt; GetPermissionsAsync(PermissionContext contexto, CancellationToken ct) =&gt;
///         await perfis.PermissoesDosPapeisAsync(contexto.TenantId, contexto.Roles, ct);
/// }
///
/// builder.Services.AddTecSecurity(builder.Configuration, security =&gt; security.UsePermissionStore&lt;PermissoesDoBanco&gt;());
/// </code>
/// </example>
public interface IPermissionStore
{
    /// <summary>Permissões da identidade. Retorne coleção vazia quando não houver.</summary>
    ValueTask<IReadOnlyCollection<string>> GetPermissionsAsync(PermissionContext context, CancellationToken cancellationToken);
}
