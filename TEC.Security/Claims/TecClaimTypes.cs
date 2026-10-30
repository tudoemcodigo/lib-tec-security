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
    /// Marca gravada na identidade normalizada, com o valor <see cref="NormalizedValue"/>. Ela só identifica a identidade dentro
    /// do cookie de sessão do login web; <b>não</b> prova a normalização. A prova é o tipo interno da identidade criada pelo
    /// <see cref="SecurityIdentityFactory"/>: um principal montado por outro código com este claim continua anônimo.
    /// </summary>
    public const string Normalized = "tec_normalized";

    /// <summary>Valor do claim <see cref="Normalized"/>.</summary>
    public const string NormalizedValue = "1";

    /// <summary>
    /// Indica que a identidade veio de um provedor multi-tenant (<see cref="ExternalIdentity.MultiTenant"/>), com o valor
    /// <see cref="MultiTenantValue"/>. A revalidação da sessão (<see cref="SecurityIdentityFactory.RevalidateAsync"/>) o lê para
    /// manter o mesmo padrão de <c>RolesAsPermissions</c> do login.
    /// </summary>
    public const string MultiTenant = "tec_multi_tenant";

    /// <summary>Valor do claim <see cref="MultiTenant"/>.</summary>
    public const string MultiTenantValue = "true";

    /// <summary><c>true</c> se o tipo de claim usa o prefixo reservado (comparação sem diferenciar maiúsculas).</summary>
    public static bool IsReserved(string claimType) =>
        claimType is not null && claimType.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
}
