namespace TEC.Security.Claims;

/// <summary>
/// Claims normalizados pelo TEC.Security: o mesmo formato para qualquer provedor de identidade (Entra ID, API key, sistema...).
/// A aplicação lê sempre estes claims (via <see cref="Abstractions.ISecurityUser"/>), nunca os claims crus do token.
/// </summary>
/// <remarks>
/// <para>Segurança: todo claim com o prefixo <see cref="Prefix"/> que chega no token é <b>descartado</b> antes da normalização.
/// Um provedor mal configurado (ex.: atributo de usuário mapeado para <c>tec_perm</c>) não consegue injetar permissões,
/// tenant ou tipo de identidade.</para>
/// <para>A identidade normalizada usa <see cref="Name"/> como <c>NameClaimType</c> e <see cref="Role"/> como
/// <c>RoleClaimType</c>: <c>User.IsInRole</c> e <c>[Authorize(Roles = ...)]</c> do ASP.NET Core passam a enxergar os papéis
/// normalizados.</para>
/// </remarks>
public static class TecClaimTypes
{
    /// <summary>Prefixo reservado dos claims normalizados.</summary>
    public const string Prefix = "tec_";

    /// <summary>Identificador estável da identidade (ex.: <c>oid</c> do Entra ID, <c>apikey:{id}</c>, <c>system:{nome}</c>).</summary>
    public const string UserId = "tec_uid";

    /// <summary>Tipo da identidade (<see cref="TEC.Core.Security.PrincipalKind"/>, por nome).</summary>
    public const string Kind = "tec_kind";

    /// <summary>Tenant da aplicação (resolvido pelo cadastro de tenants, nunca copiado do token).</summary>
    public const string TenantId = "tec_tenant";

    /// <summary>Tenant no provedor de identidade (ex.: <c>tid</c> do Entra ID).</summary>
    public const string ExternalTenantId = "tec_ext_tenant";

    /// <summary>Nome do esquema de autenticação que validou a identidade (ex.: <c>Funcionarios</c>).</summary>
    public const string Scheme = "tec_scheme";

    /// <summary>Tipo do provedor de identidade (ex.: <c>EntraId</c>, <c>ApiKey</c>, <c>System</c>).</summary>
    public const string Provider = "tec_provider";

    /// <summary>Nome de exibição (somente exibição: nunca use para decisão de acesso).</summary>
    public const string Name = "tec_name";

    /// <summary>Papel (um claim por papel).</summary>
    public const string Role = "tec_role";

    /// <summary>Escopo delegado (um claim por escopo; só em tokens de usuário).</summary>
    public const string Scope = "tec_scope";

    /// <summary>Permissão efetiva (um claim por permissão).</summary>
    public const string Permission = "tec_perm";

    /// <summary>Aplicação cliente que obteve o token (ex.: <c>azp</c> do Entra ID).</summary>
    public const string ClientId = "tec_client";

    /// <summary>
    /// Marca de identidade normalizada: só a identidade criada pelo TEC.Security tem este claim, com o valor
    /// <see cref="NormalizedValue"/>. Identidades sem a marca são tratadas como anônimas.
    /// </summary>
    public const string Normalized = "tec_normalized";

    /// <summary>Valor do claim <see cref="Normalized"/>.</summary>
    public const string NormalizedValue = "1";

    /// <summary><c>true</c> se o tipo de claim usa o prefixo reservado (comparação sem diferenciar maiúsculas).</summary>
    public static bool IsReserved(string claimType) =>
        claimType is not null && claimType.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
}
