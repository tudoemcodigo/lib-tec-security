using Microsoft.AspNetCore.Authorization;
using TEC.Security.Common;

namespace TEC.Security.AspNetCore.Authorization;

/// <summary>Tipos de identidade aceitos por <see cref="TecAuthorizeAttribute.Kinds"/>.</summary>
[Flags]
public enum TecPrincipalKinds
{
    /// <summary>Pessoa (login web ou token delegado).</summary>
    User = 1,

    /// <summary>Aplicação (client credentials, API key).</summary>
    Application = 2,

    /// <summary>Identidade de sistema criada pelo próprio processo.</summary>
    System = 4,

    /// <summary>Pessoa ou aplicação (padrão).</summary>
    UserOrApplication = User | Application,

    /// <summary>Qualquer identidade autenticada.</summary>
    Any = User | Application | System
}

/// <summary>
/// Exige identidade autenticada e normalizada pelo TEC.Security e, opcionalmente, permissões, papéis, escopos, tipos de
/// identidade e esquemas. Vale para controllers, Razor Pages, Minimal APIs (via <c>RequireTecAuthorization</c>), gRPC e hubs
/// SignalR.
/// </summary>
/// <remarks>
/// <para><b>Semântica:</b> dentro de uma propriedade, valores separados por vírgula são alternativas (basta um); entre propriedades,
/// todas precisam ser atendidas; com vários atributos (classe + método), todos precisam ser atendidos.</para>
/// <para><b>Escopos</b> só existem em tokens de usuário (delegados): com <see cref="Scopes"/> informado, tokens de aplicação são
/// negados. Para aceitar aplicações, use <see cref="Permissions"/> (app roles viram permissões).</para>
/// <para><b>Fechado por padrão:</b> sem atributo, o endpoint já exige identidade autenticada (FallbackPolicy). Valores vazios ou fora
/// do formato, ou o atributo combinado com <c>[AllowAnonymous]</c> (que o anularia), impedem a aplicação de subir.</para>
/// <para>Negado: HTTP 401 sem identidade, HTTP 403 com identidade sem permissão; corpo <c>ApiResponse</c> do TEC.Core e log de
/// auditoria (evento 3203) com o motivo.</para>
/// </remarks>
/// <example>
/// <code>
/// [TecAuthorize(Permissions = "pedidos:ler")]
/// public sealed class PedidosController : ControllerBase
/// {
///     [HttpPost, TecAuthorize(Permissions = "pedidos:criar")]                         // ler E criar
///     public IActionResult Criar(...) { ... }
///
///     [HttpDelete("{id}"), TecAuthorize(Roles = "Gerente,Admin", Kinds = TecPrincipalKinds.User)]
///     public IActionResult Excluir(Guid id) { ... }
/// }
///
/// app.MapGet("/relatorios", ...).RequireTecAuthorization(permissions: "relatorios:ler");
/// </code>
/// </example>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public sealed class TecAuthorizeAttribute : Attribute, IAuthorizeData
{
    /// <summary>Permissões aceitas, separadas por vírgula (basta uma). Ex.: <c>"pedidos:criar,pedidos:admin"</c>.</summary>
    public string? Permissions { get; set; }

    /// <summary>Papéis aceitos, separados por vírgula (basta um).</summary>
    public string? Roles { get; set; }

    /// <summary>Escopos delegados aceitos, separados por vírgula (basta um). Tokens de aplicação são negados quando informado.</summary>
    public string? Scopes { get; set; }

    /// <summary>Esquemas aceitos, separados por vírgula (ex.: <c>"Funcionarios"</c>). Padrão: qualquer esquema do TEC.Security.</summary>
    public string? Schemes { get; set; }

    /// <summary>Tipos de identidade aceitos. Padrão: <see cref="TecPrincipalKinds.UserOrApplication"/>.</summary>
    public TecPrincipalKinds Kinds { get; set; } = TecPrincipalKinds.UserOrApplication;

    // A regra viaja como nome de policy codificado (TEC|p=...|k=...), resolvido pelo TecAuthorizationPolicyProvider. Assim ela vale
    // em todo lugar que lê IAuthorizeData: middleware, filtros MVC, métodos de hub SignalR e AuthorizeRouteView do Blazor
    // (IAuthorizationRequirementData só é lido pelo middleware). Esquemas são conferidos pelo claim tec_scheme.
    string? IAuthorizeData.Policy { get => TecPolicyName.Encode(ToRequirement()); set => throw new NotSupportedException("Use Permissions/Roles/Scopes."); }

    string? IAuthorizeData.Roles { get => null; set => throw new NotSupportedException("Use a propriedade Roles."); }

    string? IAuthorizeData.AuthenticationSchemes { get => null; set => throw new NotSupportedException("Use a propriedade Schemes."); }

    /// <summary>Requisito equivalente (para avaliação manual com <c>IAuthorizationService</c>).</summary>
    public IAuthorizationRequirement GetRequirement() => ToRequirement();

    /// <summary>Converte em requisito, validando os valores.</summary>
    /// <exception cref="InvalidOperationException">Valor vazio ou fora do formato.</exception>
    internal TecRequirement ToRequirement()
    {
        if ((Kinds & TecPrincipalKinds.Any) == 0 || (Kinds & ~TecPrincipalKinds.Any) != 0)
            throw new InvalidOperationException("[TecAuthorize]: Kinds inválido.");

        return new TecRequirement(
            Parse(Permissions, nameof(Permissions)),
            Parse(Roles, nameof(Roles)),
            Parse(Scopes, nameof(Scopes)),
            Parse(Schemes, nameof(Schemes)),
            Kinds);
    }

    private static string[] Parse(string? value, string property)
    {
        if (value is null)
            return [];

        string[] items = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (items.Length == 0)
            throw new InvalidOperationException($"[TecAuthorize]: {property} informado sem nenhum valor (a regra degradaria para 'qualquer autenticado').");

        if (items.Any(i => !SecurityRules.IsValidName(i)))
            throw new InvalidOperationException($"[TecAuthorize]: {property} contém valor fora do formato (letras, dígitos e _ . : / -).");

        return [.. items.Distinct(StringComparer.Ordinal)];
    }
}
