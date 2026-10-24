using System.Security.Claims;
using TEC.Core.Security;

namespace TEC.Security.Claims;

/// <summary>
/// Identidade já validada por um provedor (token, API key, sistema), no formato neutro que o
/// <see cref="SecurityIdentityFactory"/> converte em claims normalizados. Preenchida pelos pacotes de provedor.
/// </summary>
public sealed class ExternalIdentity
{
    /// <summary>Esquema de autenticação (ex.: <c>Funcionarios</c>). Obrigatório.</summary>
    public required string Scheme { get; init; }

    /// <summary>Tipo do provedor (ex.: <c>EntraId</c>). Obrigatório; também é a chave em <c>Tenants:*:IdentityProviders</c>.</summary>
    public required string Provider { get; init; }

    /// <summary>Identificador estável e não reutilizável (ex.: <c>oid</c>). Obrigatório.</summary>
    public required string UserId { get; init; }

    /// <summary>Tipo da identidade: <see cref="PrincipalKind.User"/> ou <see cref="PrincipalKind.Application"/> (ou System, só internamente).</summary>
    public required PrincipalKind Kind { get; init; }

    /// <summary>Tenant no provedor (ex.: <c>tid</c>), convertido no tenant da aplicação pelo cadastro.</summary>
    public string? ExternalTenantId { get; init; }

    /// <summary>
    /// Tenant da aplicação já conhecido por configuração confiável (ex.: API key cadastrada). Tem precedência sobre
    /// <see cref="ExternalTenantId"/> e também precisa existir e estar ativo no cadastro.
    /// </summary>
    public string? TenantId { get; init; }

    /// <summary>Nome de exibição.</summary>
    public string? Name { get; init; }

    /// <summary>Aplicação cliente que obteve o token.</summary>
    public string? ClientId { get; init; }

    /// <summary>Papéis informados pelo provedor.</summary>
    public IReadOnlyCollection<string> Roles { get; init; } = [];

    /// <summary>Escopos delegados (somente <see cref="PrincipalKind.User"/>).</summary>
    public IReadOnlyCollection<string> Scopes { get; init; } = [];

    /// <summary>Permissões concedidas diretamente (ex.: configuradas na API key), somadas às do <c>IPermissionStore</c>.</summary>
    public IReadOnlyCollection<string> Permissions { get; init; } = [];

    /// <summary>
    /// Claims originais do provedor, copiados para a identidade normalizada (exceto os com prefixo <c>tec_</c>, sempre
    /// descartados). Ficam disponíveis em <c>ISecurityUser.Principal</c> para leitura de dados específicos do provedor.
    /// </summary>
    public IEnumerable<Claim> SourceClaims { get; init; } = [];
}
