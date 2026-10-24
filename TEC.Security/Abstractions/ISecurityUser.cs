using System.Security.Claims;
using TEC.Core.Security;

namespace TEC.Security.Abstractions;

/// <summary>
/// Identidade da operação atual com papéis, escopos e permissões já normalizados, igual para qualquer provedor de identidade.
/// Registrado como Scoped; também disponível como <see cref="ICurrentUser"/> (TEC.Core) para componentes que só precisam
/// de id e tenant (auditoria).
/// </summary>
/// <remarks>
/// <para>Lido somente dos claims normalizados (<see cref="Claims.TecClaimTypes"/>) de uma identidade criada pelo TEC.Security.
/// Uma identidade autenticada por outro mecanismo (sem a marca de normalização) é tratada como anônima: falha fechada.</para>
/// <para>Origem do usuário, nesta ordem: a identidade definida por <see cref="ISecurityContext.RunAs"/> (workers, mensageria)
/// e, em ASP.NET Core, o <c>HttpContext.User</c>.</para>
/// </remarks>
/// <example>
/// <code>
/// public sealed class PedidoService(ISecurityUser usuario)
/// {
///     public Result Cancelar(Pedido pedido) =>
///         usuario.HasPermission("pedidos:cancelar") &amp;&amp; pedido.TenantId == usuario.TenantId
///             ? pedido.Cancelar(usuario.Id!)
///             : SecurityErrors.Forbidden();
/// }
/// </code>
/// </example>
public interface ISecurityUser : ICurrentUser
{
    /// <summary>Nome de exibição (somente exibição: nunca use em decisão de acesso).</summary>
    string? Name { get; }

    /// <summary>Esquema de autenticação que validou a identidade (ex.: <c>Funcionarios</c>).</summary>
    string? Scheme { get; }

    /// <summary>Tipo do provedor de identidade (ex.: <c>EntraId</c>, <c>ApiKey</c>, <c>System</c>).</summary>
    string? Provider { get; }

    /// <summary>Tenant no provedor de identidade (ex.: <c>tid</c> do Entra ID).</summary>
    string? ExternalTenantId { get; }

    /// <summary>Aplicação cliente que obteve o token, quando o provedor informa.</summary>
    string? ClientId { get; }

    /// <summary>Papéis normalizados.</summary>
    IReadOnlySet<string> Roles { get; }

    /// <summary>Escopos delegados (somente tokens de usuário).</summary>
    IReadOnlySet<string> Scopes { get; }

    /// <summary>Permissões efetivas (papéis convertidos pelo <see cref="IPermissionStore"/> e, se configurado, os próprios papéis).</summary>
    IReadOnlySet<string> Permissions { get; }

    /// <summary>Identidade completa, para casos não cobertos pelas propriedades (ex.: ler um claim específico do provedor).</summary>
    ClaimsPrincipal? Principal { get; }

    /// <summary>Tem o papel (comparação exata, diferenciando maiúsculas)?</summary>
    bool IsInRole(string role);

    /// <summary>Tem o escopo delegado (comparação exata)?</summary>
    bool HasScope(string scope);

    /// <summary>Tem a permissão (comparação exata)?</summary>
    bool HasPermission(string permission);
}
