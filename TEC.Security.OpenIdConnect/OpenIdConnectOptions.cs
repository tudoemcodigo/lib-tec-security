using TEC.Security.Resilience;

namespace TEC.Security.OpenIdConnect;

/// <summary>Configurações de validação de tokens JWT Bearer de um provedor OpenID Connect (ex.: Keycloak, Auth0, Okta, Entra ID).</summary>
public sealed class OpenIdConnectApiOptions
{
    /// <summary>URL base do provedor OpenID Connect (ex.: <c>https://auth.empresa.com/realms/corp</c>). Obrigatório.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Audiência principal esperada no token (ex.: <c>api-pedidos</c> ou client-id). Opcional se <see cref="Audiences"/> for preenchido.</summary>
    public string? Audience { get; set; }

    /// <summary>Lista de audiências aceitas pela API.</summary>
    public List<string> Audiences { get; set; } = [];

    /// <summary>Emissores adicionais aceitos (útil em cenários multi-tenant onde cada tenant possui um realm ou emissor específico).</summary>
    public List<string> ValidIssuers { get; set; } = [];

    /// <summary>Exige metadados e chaves JWKS exclusivamente via HTTPS (permitido falso apenas para Authority em loopback local). Padrão: <c>true</c>.</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Se ativado, valida que o emissor (<c>iss</c>) pertença a um tenant ativo no cadastro de tenants (<c>ITenantRegistry</c>). Padrão: <c>false</c>.
    /// </summary>
    public bool MultiTenant { get; set; }

    /// <summary>Claim personalizada para resolução de tenant (se não especificada, infere pelo emissor ou claim <c>tid</c>/<c>tenant</c>).</summary>
    public string? TenantClaim { get; set; }

    /// <summary>Claim usada para extrair papéis do usuário. Padrão: <c>roles</c>.</summary>
    public string RoleClaimType { get; set; } = "roles";

    /// <summary>Claim usada para extrair o nome de exibição. Padrão: <c>preferred_username</c>.</summary>
    public string NameClaimType { get; set; } = "preferred_username";

    /// <summary>Algoritmos de assinatura aceitos. Padrão: RS256, PS256, ES256.</summary>
    public List<string> ValidAlgorithms { get; set; } =
        [Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSsaPssSha256, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256];
}

/// <summary>Configurações de login web interativo via OpenID Connect (Authorization Code com PKCE).</summary>
public sealed class OpenIdConnectWebLoginOptions
{
    /// <summary>URL base do provedor OpenID Connect. Obrigatório.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>Identificador público da aplicação cliente registrada no IdP. Obrigatório.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Client secret diretamente na configuração (desencorajado em produção; prefira <see cref="ClientSecretName"/>).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Nome do segredo no TEC.Vault contendo o client secret da aplicação web.</summary>
    public string? ClientSecretName { get; set; }

    /// <summary>Escopos adicionais solicitados no login (ex.: <c>profile</c>, <c>email</c>). <c>openid</c> é sempre adicionado.</summary>
    public List<string> Scopes { get; set; } = ["profile", "email"];

    /// <summary>Exige metadados exclusivamente via HTTPS. Padrão: <c>true</c>.</summary>
    public bool RequireHttpsMetadata { get; set; } = true;
}

/// <summary>Como a aplicação se autentica no fluxo M2M Client Credentials.</summary>
public enum OpenIdConnectM2MAuthType
{
    /// <summary>Segredo do cliente (direto ou lido de forma segura do TEC.Vault).</summary>
    ClientSecret = 0,

    /// <summary>
    /// Asserção JWT privada (Private Key JWT / RFC 7523) assinada via certificado ou chave PS256/RS256 dentro do TEC.Vault, sem exportar a chave privada.
    /// </summary>
    PrivateKeyJwt = 1
}

/// <summary>Configurações de obtenção de token de serviço M2M (OAuth 2.0 Client Credentials - RFC 6749).</summary>
public sealed class OpenIdConnectClientOptions
{
    /// <summary>URL base do provedor OpenID Connect (ex.: <c>https://auth.empresa.com/realms/corp</c>).</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// URL direta do endpoint de token (opcional; se não informado, infere como <c>{Authority}/protocol/openid-connect/token</c> ou <c>{Authority}/oauth2/token</c>).
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>Identificador da aplicação cliente (Client ID). Obrigatório.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Tipo de autenticação no endpoint de token. Padrão: <see cref="OpenIdConnectM2MAuthType.ClientSecret"/>.</summary>
    public OpenIdConnectM2MAuthType AuthType { get; set; } = OpenIdConnectM2MAuthType.ClientSecret;

    /// <summary>Client secret fixo (desencorajado em produção; prefira <see cref="ClientSecretName"/>).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Nome do segredo do TEC.Vault contendo o client secret.</summary>
    public string? ClientSecretName { get; set; }

    /// <summary>Nome do certificado no TEC.Vault para assinatura de PrivateKeyJwt (RFC 7523).</summary>
    public string? CertificateName { get; set; }

    /// <summary>Opções de circuit breaker e resiliência nas chamadas ao IdP.</summary>
    public SecurityCircuitBreakerOptions Resilience { get; } = new();

    /// <summary>Tempo limite por tentativa de requisição HTTP ao endpoint de token. Padrão: 10 segundos.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
}
