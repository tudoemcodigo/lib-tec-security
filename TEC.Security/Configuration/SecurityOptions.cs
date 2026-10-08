namespace TEC.Security.Configuration;

/// <summary>Opções gerais do TEC.Security (seção <c>Security</c>).</summary>
/// <example>
/// <code>
/// "Security": {
///   "RequireTenant": true,
///   "RolesAsPermissions": true,
///   "Tenants": { ... },        // TenantOptions
///   "Permissions": { ... },    // PermissionOptions
///   "ApiKeys": { ... }         // ApiKeyOptions
/// }
/// </code>
/// </example>
public sealed class SecurityOptions
{
    /// <summary>Nome da seção de configuração.</summary>
    public const string SectionName = "Security";

    /// <summary>
    /// Exige que toda identidade (exceto sistema sem tenant) pertença a um tenant cadastrado e ativo. Identidades sem tenant
    /// não autenticam (HTTP 401). Padrão: <c>false</c> (aplicação sem tenants ou com tenant opcional).
    /// </summary>
    public bool RequireTenant { get; set; }

    /// <summary>
    /// Os próprios papéis da identidade também contam como permissões (ex.: app role <c>clientes:escrever</c> do Entra ID atende
    /// <c>[TecAuthorize(Permissions = "clientes:escrever")]</c>). Somados às permissões do <c>IPermissionStore</c>. Padrão: <c>true</c>.
    /// </summary>
    public bool RolesAsPermissions { get; set; } = true;
}

/// <summary>
/// Cadastro de tenants (seção <c>Security:Tenants</c>), lido com recarga. Cada chave é o id do tenant na aplicação.
/// </summary>
/// <example>
/// <code>
/// "Security": {
///   "Tenants": {
///     "contoso": {
///       "Name": "Contoso Ltda",
///       "Enabled": true,
///       "IdentityProviders": { "EntraId": [ "&lt;tenant-id-do-entra&gt;" ] }
///     }
///   }
/// }
/// </code>
/// </example>
public sealed class TenantOptions
{
    /// <summary>Nome da seção de configuração.</summary>
    public const string SectionName = "Security:Tenants";

    /// <summary>Tenants por id da aplicação.</summary>
    public Dictionary<string, TenantDefinition> Items { get; } = new(StringComparer.Ordinal);
}

/// <summary>Um tenant do cadastro.</summary>
public sealed class TenantDefinition
{
    /// <summary>Nome de exibição.</summary>
    public string? Name { get; set; }

    /// <summary>Tenant ativo. Padrão: <c>true</c>. Inativo: identidades dele não autenticam (inclusive sessões já abertas).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Tenants dos provedores de identidade vinculados a este tenant, por tipo de provedor (ex.: <c>EntraId</c> → lista de
    /// <c>tid</c>). Um mesmo id externo não pode aparecer em dois tenants.
    /// </summary>
    public Dictionary<string, List<string>> IdentityProviders { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Mapeamento papel → permissões (seção <c>Security:Permissions</c>), lido com recarga.</summary>
/// <example>
/// <code>
/// "Security": {
///   "Permissions": {
///     "Roles": {
///       "Vendedor": [ "pedidos:ler", "pedidos:criar" ],
///       "Gerente":  [ "pedidos:ler", "pedidos:criar", "pedidos:cancelar" ]
///     }
///   }
/// }
/// </code>
/// </example>
public sealed class PermissionOptions
{
    /// <summary>Nome da seção de configuração.</summary>
    public const string SectionName = "Security:Permissions";

    /// <summary>Permissões por papel (comparação exata do nome do papel), válidas para identidades de qualquer tenant.</summary>
    public Dictionary<string, List<string>> Roles { get; set; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Permissões por papel válidas <b>somente</b> para identidades do tenant (chave = id do tenant na aplicação), somadas às de
    /// <see cref="Roles"/>. Em APIs multi-tenant, administradores de cada tenant cliente conseguem atribuir qualquer app role
    /// aos próprios usuários: mantenha permissões privilegiadas só no mapeamento do tenant da sua empresa e use
    /// <c>RolesAsPermissions = false</c>.
    /// </summary>
    public Dictionary<string, TenantPermissionOptions> Tenants { get; set; } = new(StringComparer.Ordinal);
}

/// <summary>Mapeamento papel → permissões de um tenant.</summary>
public sealed class TenantPermissionOptions
{
    /// <summary>Permissões por papel.</summary>
    public Dictionary<string, List<string>> Roles { get; set; } = new(StringComparer.Ordinal);
}

/// <summary>API keys aceitas (seção <c>Security:ApiKeys</c>), lidas com recarga. Só o hash da chave fica na configuração.</summary>
/// <example>
/// <code>
/// "Security": {
///   "ApiKeys": {
///     "HeaderName": "X-Api-Key",
///     "Keys": {
///       "erp-contoso": {
///         "Hash": "&lt;hash gerado por ApiKeyGenerator&gt;",
///         "TenantId": "contoso",
///         "Permissions": [ "pedidos:ler" ],
///         "ExpiresOn": "2027-06-30T00:00:00Z"
///       }
///     }
///   }
/// }
/// </code>
/// </example>
public sealed class ApiKeyOptions
{
    /// <summary>Nome da seção de configuração.</summary>
    public const string SectionName = "Security:ApiKeys";

    /// <summary>Header HTTP que traz a chave. Padrão: <c>X-Api-Key</c>. A chave nunca é aceita na query string.</summary>
    public string HeaderName { get; set; } = "X-Api-Key";

    /// <summary>Chaves por id (o id faz parte da chave: <c>tec_{id}_{segredo}</c>).</summary>
    public Dictionary<string, ApiKeyDefinition> Keys { get; set; } = new(StringComparer.Ordinal);
}

/// <summary>Uma API key cadastrada.</summary>
public sealed class ApiKeyDefinition
{
    /// <summary>SHA-256 do segredo, em Base64Url (gerado por <c>ApiKeyGenerator.Generate</c>). Obrigatório.</summary>
    public string? Hash { get; set; }

    /// <summary>Nome de exibição (ex.: sistema integrado).</summary>
    public string? Name { get; set; }

    /// <summary>Tenant da aplicação ao qual a chave pertence (precisa existir no cadastro).</summary>
    public string? TenantId { get; set; }

    /// <summary>Papéis da chave.</summary>
    public List<string> Roles { get; set; } = [];

    /// <summary>Permissões da chave (somadas às do <c>IPermissionStore</c> para os papéis).</summary>
    public List<string> Permissions { get; set; } = [];

    /// <summary>Chave ativa. Padrão: <c>true</c>.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Expiração (UTC). <b>Obrigatória</b>: chaves sem validade não são aceitas.</summary>
    public DateTimeOffset? ExpiresOn { get; set; }
}
