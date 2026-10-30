using TEC.Security.Resilience;

namespace TEC.Security.OpenIdConnect;

/// <summary>Configurações de validação de tokens JWT Bearer de um provedor OpenID Connect (ex.: Keycloak, Auth0, Okta, Entra ID).</summary>
public sealed class OpenIdConnectApiOptions
{
    /// <summary>
    /// URL base do provedor OpenID Connect (ex.: <c>https://auth.empresa.com/realms/corp</c>). Obrigatório. É o emissor aceito e a
    /// origem dos metadados e das chaves (JWKS).
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Audiência principal esperada no token (ex.: <c>api-pedidos</c> ou client-id). Opcional se <see cref="Audiences"/> for
    /// preenchido. Também é o client cujos papéis são lidos de <c>resource_access</c> (Keycloak).
    /// </summary>
    public string? Audience { get; set; }

    /// <summary>Lista de audiências aceitas pela API (e clients cujos papéis são lidos de <c>resource_access</c>).</summary>
    public List<string> Audiences { get; set; } = [];

    /// <summary>
    /// Emissores aceitos além da <see cref="Authority"/>, só com <see cref="MultiTenant"/> = <c>true</c>: sem ele, o seletor de
    /// esquema só reconhece tokens cujo <c>iss</c> é a <see cref="Authority"/>. As chaves continuam vindo do JWKS da
    /// <see cref="Authority"/>, então só servem para IdPs que assinam os tokens de vários emissores com as mesmas chaves (ex.:
    /// Entra ID). O <c>tid</c> do token não é conferido contra o emissor.
    /// </summary>
    public List<string> ValidIssuers { get; set; } = [];

    /// <summary>Exige metadados e chaves JWKS exclusivamente via HTTPS (permitido falso apenas para Authority em loopback local). Padrão: <c>true</c>.</summary>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Exige que o tenant do token (claim de tenant ou, sem ele, o <c>iss</c>) esteja cadastrado e ativo no <c>ITenantRegistry</c>
    /// para o provedor <c>OpenIdConnect</c>; senão o token é recusado. Também deixa <c>RolesAsPermissions</c> em <c>false</c>
    /// quando não definido. Padrão: <c>false</c>.
    /// </summary>
    public bool MultiTenant { get; set; }

    /// <summary>Claim personalizada para resolução de tenant (se não especificada, usa <c>tid</c>, <c>tenant_id</c> ou <c>tenant</c> e, sem eles, o emissor).</summary>
    public string? TenantClaim { get; set; }

    /// <summary>Claim usada para extrair papéis do usuário. Padrão: <c>roles</c>.</summary>
    public string RoleClaimType { get; set; } = "roles";

    /// <summary>Claim usada para extrair o nome de exibição (só exibição). Padrão: <c>preferred_username</c>.</summary>
    public string NameClaimType { get; set; } = "preferred_username";

    /// <summary>Algoritmos de assinatura aceitos. Padrão: RS256, PS256, ES256.</summary>
    public List<string> ValidAlgorithms { get; set; } =
        [Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSha256, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.RsaSsaPssSha256, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.EcdsaSha256];

    /// <summary>
    /// Regras que decidem se o token é de usuário ou de aplicação (<c>Kind</c>). O padrão recusa o token que nenhuma regra
    /// reconhece, em vez de supor <c>User</c>: veja <see cref="OpenIdConnectKindOptions"/>.
    /// </summary>
    public OpenIdConnectKindOptions Kind { get; } = new();
}

/// <summary>O que fazer com um token que nenhuma regra de <see cref="OpenIdConnectKindOptions"/> classifica.</summary>
public enum OpenIdConnectUnresolvedKind
{
    /// <summary>Recusa o token (HTTP 401). Padrão: um token de aplicação não reconhecido nunca passa como pessoa, nem o contrário.</summary>
    Reject = 0,

    /// <summary>Trata como usuário. Use só se toda aplicação do IdP for reconhecida por uma regra (ex.: Auth0, com <c>gty</c>).</summary>
    User = 1,

    /// <summary>Trata como aplicação. Use só se todo usuário do IdP for reconhecido por uma regra.</summary>
    Application = 2
}

/// <summary>
/// Regras que decidem o tipo da identidade (<c>Kind</c>) de um access token: usuário (<c>User</c>) ou aplicação
/// (<c>Application</c>). <c>[TecAuthorize(Kinds = ...)]</c>, os escopos (só de usuário) e o <c>IPermissionStore</c> dependem
/// dessa decisão.
/// </summary>
/// <remarks>
/// <para>Regras de claim no formato <c>claim=valor</c>: comparação exata e com diferença de maiúsculas; <c>claim=*</c> aceita
/// qualquer valor e um valor terminado em <c>*</c> é prefixo (ex.: <c>client_id=*</c>, <c>sub=svc-*</c>). Claims editáveis pelo
/// usuário ou pelo administrador do tenant (<c>preferred_username</c>, <c>name</c>, <c>email</c>, <c>upn</c>...) e os claims
/// <c>tec_*</c> não são aceitos em regra: a configuração inválida impede a subida.</para>
/// <para>Decisão: sinais de aplicação e de usuário no mesmo token recusam o token; só sinais de um tipo decidem; nenhum sinal
/// aplica <see cref="Unresolved"/> (padrão: recusa). A recusa é a escolha que falha fechada: supor <c>User</c> deixaria um token
/// de aplicação passar em endpoints com <c>Kinds = User</c> (e com escopos), e supor <c>Application</c> deixaria um token de
/// pessoa passar em endpoints com <c>Kinds = Application</c>.</para>
/// <para>O login web não usa estas regras: o ID token de um login interativo é sempre de uma pessoa (<c>User</c>).</para>
/// </remarks>
public sealed class OpenIdConnectKindOptions
{
    /// <summary>
    /// Claims que indicam token de aplicação. Padrão: <c>idtyp=app</c> (claim opcional do Entra ID) e
    /// <c>gty=client-credentials</c> (Auth0).
    /// </summary>
    public List<string> ApplicationClaims { get; set; } = ["idtyp=app", "gty=client-credentials"];

    /// <summary>
    /// Claims que indicam token de usuário. Padrão: <c>idtyp=user</c>, <c>sid=*</c> (sessão do usuário no IdP) e
    /// <c>auth_time=*</c> (instante do login do usuário).
    /// </summary>
    public List<string> UserClaims { get; set; } = ["idtyp=user", "sid=*", "auth_time=*"];

    /// <summary>
    /// <c>sub</c> igual a <c>azp</c>, <c>client_id</c>, <c>clientId</c>, <c>cid</c> ou <c>appid</c> indica aplicação: o cliente
    /// obteve o token em nome próprio (RFC 9068, Okta, Cognito). Padrão: <c>true</c>.
    /// </summary>
    public bool ApplicationWhenSubjectIsClient { get; set; } = true;

    /// <summary>
    /// Regra do Microsoft Entra ID: token com <c>scp</c> é de usuário (permissão delegada); sem <c>scp</c> (ou com <c>scp</c> vazio
    /// ou <c>/</c>) é de aplicação (app-only, com os app roles em <c>roles</c>). Padrão (<c>null</c>): ligada quando a
    /// <see cref="OpenIdConnectApiOptions.Authority"/> é do Entra ID (<c>login.microsoftonline.com</c>,
    /// <c>login.microsoftonline.us</c>, <c>login.partner.microsoftonline.cn</c>, <c>login.chinacloudapi.cn</c> ou
    /// <c>*.ciamlogin.com</c>) e desligada para os demais IdPs.
    /// </summary>
    public bool? UseEntraIdScpRule { get; set; }

    /// <summary>Quando nenhuma regra decide. Padrão: <see cref="OpenIdConnectUnresolvedKind.Reject"/>.</summary>
    public OpenIdConnectUnresolvedKind Unresolved { get; set; } = OpenIdConnectUnresolvedKind.Reject;
}

/// <summary>Configurações de login web interativo via OpenID Connect (Authorization Code com PKCE).</summary>
public sealed class OpenIdConnectWebLoginOptions
{
    /// <summary>URL base do provedor OpenID Connect. Obrigatório.</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Identificador público da aplicação cliente registrada no IdP. Obrigatório. Também é o único client cujos papéis são lidos
    /// de <c>resource_access</c> (Keycloak).
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Client secret diretamente na configuração (desencorajado em produção; prefira <see cref="ClientSecretName"/>).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Nome do segredo no TEC.Vault com o client secret da aplicação web. Conferido na subida (o segredo precisa existir) e lido de
    /// novo a cada login, na troca do código e no pedido de autorização enviado por PAR: a rotação no cofre vale sem reiniciar.
    /// </summary>
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
    /// Reservado para a asserção JWT assinada (Private Key JWT, RFC 7523), que <b>não</b> está implementada: com este valor a
    /// validação das opções impede a subida e o construtor do <see cref="OpenIdConnectAccessTokenProvider"/> lança
    /// <see cref="NotSupportedException"/>.
    /// </summary>
    PrivateKeyJwt = 1
}

/// <summary>Configurações de obtenção de token de serviço M2M (OAuth 2.0 Client Credentials - RFC 6749).</summary>
/// <remarks>
/// Validadas na subida do host (<c>ValidateOnStart</c>) quando registradas com <c>AddOpenIdConnectClient</c>: sem
/// <see cref="ClientId"/>, sem endpoint, endpoint ou <see cref="Authority"/> sem HTTPS (exceto loopback), sem segredo,
/// <see cref="ClientSecretName"/> sem <c>ISecretReader</c> registrado, <see cref="Timeout"/> fora do limite, resiliência inválida
/// ou <see cref="OpenIdConnectM2MAuthType.PrivateKeyJwt"/> impedem a aplicação de subir.
/// </remarks>
public sealed class OpenIdConnectClientOptions
{
    /// <summary>URL base do provedor OpenID Connect (ex.: <c>https://auth.empresa.com/realms/corp</c>).</summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// URL direta do endpoint de token. Se não informada, é inferida como <c>{Authority}/protocol/openid-connect/token</c> (padrão
    /// do Keycloak); para outros IdPs (Entra ID, Auth0, Okta...) informe-a.
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>Identificador da aplicação cliente (Client ID). Obrigatório.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Tipo de autenticação no endpoint de token. Padrão: <see cref="OpenIdConnectM2MAuthType.ClientSecret"/> (o único suportado).</summary>
    public OpenIdConnectM2MAuthType AuthType { get; set; } = OpenIdConnectM2MAuthType.ClientSecret;

    /// <summary>Client secret fixo (desencorajado em produção; prefira <see cref="ClientSecretName"/>).</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Nome do segredo do TEC.Vault contendo o client secret, lido a cada obtenção de token.</summary>
    public string? ClientSecretName { get; set; }

    /// <summary>Não usado: reservado para <see cref="OpenIdConnectM2MAuthType.PrivateKeyJwt"/>, que não está implementado.</summary>
    public string? CertificateName { get; set; }

    /// <summary>Opções de circuit breaker e resiliência nas chamadas ao IdP.</summary>
    public SecurityCircuitBreakerOptions Resilience { get; } = new();

    /// <summary>
    /// Tempo limite de cada pedido ao endpoint de token, do envio até a leitura completa da resposta (maior que zero, até 5
    /// minutos). Padrão: 10 segundos.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(10);
}
