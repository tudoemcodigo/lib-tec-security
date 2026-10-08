namespace TEC.Security.EntraId;

/// <summary>Como a aplicação prova a própria identidade ao Entra ID (login web, chamadas entre serviços, On-Behalf-Of).</summary>
public enum EntraIdCredentialType
{
    /// <summary>
    /// Identidade gerenciada federada à app registration (federated identity credential com emissor da identidade gerenciada).
    /// Sem nenhum segredo. <b>Recomendado no Azure</b> (App Service, Container Apps, AKS, VMs). Vale para todos os fluxos.
    /// </summary>
    ManagedIdentityFederation = 0,

    /// <summary>
    /// Workload Identity federada (AKS, GitHub Actions/OIDC): lê AZURE_FEDERATED_TOKEN_FILE. Sem segredo. Vale para todos os fluxos.
    /// </summary>
    WorkloadIdentity = 1,

    /// <summary>
    /// Certificado guardado no TEC.Vault (<see cref="EntraIdCredentialOptions.CertificateName"/>). A assinatura da client assertion
    /// (PS256) é feita <b>dentro do cofre</b>: a chave privada nunca sai de lá (o certificado pode ser não exportável).
    /// </summary>
    Certificate = 2,

    /// <summary>
    /// Client secret guardado no TEC.Vault (<see cref="EntraIdCredentialOptions.ClientSecretName"/>). Desencorajado: segredo
    /// compartilhado, que vaza e expira. Use só quando nenhuma opção acima for possível.
    /// </summary>
    ClientSecret = 3,

    /// <summary>
    /// A própria identidade gerenciada como identidade da aplicação (sem app registration). Só para chamadas entre serviços
    /// (client credentials); não serve para login web nem On-Behalf-Of.
    /// </summary>
    ManagedIdentity = 4,

    /// <summary>
    /// Credenciais do desenvolvedor (Azure CLI, Azure Developer CLI, Visual Studio). Só em Development (falha fechada fora dele)
    /// e só para chamadas entre serviços.
    /// </summary>
    Developer = 5
}

/// <summary>Credencial da aplicação no Entra ID. Nenhum valor secreto fica na configuração: só o nome do item no cofre.</summary>
public sealed class EntraIdCredentialOptions
{
    /// <summary>Tipo da credencial. Padrão: <see cref="EntraIdCredentialType.ManagedIdentityFederation"/>.</summary>
    public EntraIdCredentialType Type { get; set; } = EntraIdCredentialType.ManagedIdentityFederation;

    /// <summary>Client id da identidade gerenciada atribuída pelo usuário (<c>null</c> = atribuída pelo sistema).</summary>
    public string? ManagedIdentityClientId { get; set; }

    /// <summary>Nome do certificado no TEC.Vault (<see cref="EntraIdCredentialType.Certificate"/>).</summary>
    public string? CertificateName { get; set; }

    /// <summary>Nome do segredo no TEC.Vault (<see cref="EntraIdCredentialType.ClientSecret"/>).</summary>
    public string? ClientSecretName { get; set; }

    /// <summary>Permite <see cref="EntraIdCredentialType.Developer"/> fora de Development (CI, ferramentas). Padrão: <c>false</c>.</summary>
    public bool AllowDeveloperCredentialsOutsideDevelopment { get; set; }
}

/// <summary>Configuração comum de uma app registration do Entra ID.</summary>
public abstract class EntraIdAppOptions
{
    /// <summary>
    /// Instância (nuvem) do Entra ID. Padrão: <c>https://login.microsoftonline.com/</c>. Aceitas: nuvem pública, governo dos
    /// EUA (<c>login.microsoftonline.us</c>) e China (<c>login.chinacloudapi.cn</c>, <c>login.partner.microsoftonline.cn</c>).
    /// </summary>
    public string Instance { get; set; } = "https://login.microsoftonline.com/";

    /// <summary>Tenant da app registration (GUID). Obrigatório sem <see cref="MultiTenant"/>.</summary>
    public string? TenantId { get; set; }

    /// <summary>Client id da app registration (GUID). Obrigatório.</summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Aceita usuários/aplicações de outros tenants do Entra ID: somente os <b>ativos</b> no cadastro
    /// (<c>Security:Tenants:*:IdentityProviders:EntraId</c>, com recarga) e os de <see cref="AllowedTenantIds"/>, além de
    /// <see cref="TenantId"/>. Nunca "qualquer tenant". Padrão: <c>false</c>.
    /// </summary>
    public bool MultiTenant { get; set; }

    /// <summary>Tenants liberados fixos (GUIDs), além do cadastro. Use o cadastro de tenants para liberar e bloquear sem deploy.</summary>
    public List<string> AllowedTenantIds { get; set; } = [];
}

/// <summary>Validação de tokens de uma API protegida pelo Entra ID (<c>AddEntraIdApi</c>).</summary>
/// <example>
/// <code>
/// "Security": {
///   "EntraId": {
///     "Api": {
///       "TenantId": "&lt;tenant-id&gt;",
///       "ClientId": "&lt;client-id-da-api&gt;",
///       "MultiTenant": true,
///       "AllowedClientApplications": [ "&lt;client-id-do-front&gt;" ]
///     }
///   }
/// }
/// </code>
/// </example>
public sealed class EntraIdApiOptions : EntraIdAppOptions
{
    /// <summary>
    /// Audiências aceitas. Padrão (lista vazia): o <see cref="EntraIdAppOptions.ClientId"/> (tokens v2) e
    /// <c>api://{ClientId}</c> (Application ID URI padrão).
    /// </summary>
    public List<string> Audiences { get; set; } = [];

    /// <summary>
    /// Aplicações cliente aceitas (client id em <c>azp</c>/<c>appid</c>). Vazio: qualquer aplicação a que o Entra ID tenha
    /// emitido token para esta API. Recomendado preencher: limita quem pode chamar a API mesmo com consentimento indevido.
    /// </summary>
    public List<string> AllowedClientApplications { get; set; } = [];

    /// <summary>Aceita tokens de aplicação (client credentials, sem usuário). Padrão: <c>true</c>.</summary>
    public bool AllowApplicationTokens { get; set; } = true;

    /// <summary>Aceita tokens v1.0 (emissor <c>sts.windows.net</c>). Padrão: <c>false</c> (configure <c>accessTokenAcceptedVersion: 2</c> no manifesto).</summary>
    public bool AcceptV1Tokens { get; set; }
}

/// <summary>Login web com o Entra ID (<c>AddEntraIdWebLogin</c>).</summary>
/// <example>
/// <code>
/// "Security": {
///   "EntraId": {
///     "WebLogin": {
///       "TenantId": "&lt;tenant-id&gt;",
///       "ClientId": "&lt;client-id-do-site&gt;",
///       "Credential": { "Type": "Certificate", "CertificateName": "entra-site" }
///     }
///   }
/// }
/// </code>
/// </example>
public sealed class EntraIdWebLoginOptions : EntraIdAppOptions
{
    /// <summary>Caminho de retorno do login (registrar como Redirect URI <c>https://&lt;host&gt;/signin-oidc</c>).</summary>
    public string CallbackPath { get; set; } = "/signin-oidc";

    /// <summary>Caminho de retorno do logout.</summary>
    public string SignedOutCallbackPath { get; set; } = "/signout-callback-oidc";

    /// <summary>Credencial da aplicação para trocar o código de autorização por tokens.</summary>
    public EntraIdCredentialOptions Credential { get; set; } = new();

    /// <summary>Duração da sessão (cookie). Padrão: 1 hora (máximo 12 horas), renovada com o uso.</summary>
    public TimeSpan SessionDuration { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Intervalo de revalidação de tenant e permissões da sessão. Padrão: 5 minutos.</summary>
    public TimeSpan RevalidationInterval { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Duração máxima absoluta da sessão desde o login (o uso não estende). Depois dela o usuário passa pelo Entra ID de novo,
    /// que barra conta desativada e papéis removidos. Padrão: 8 horas (1 a 24 horas).
    /// </summary>
    public TimeSpan MaxSessionLifetime { get; set; } = TimeSpan.FromHours(8);
}

/// <summary>Identidade da aplicação para chamar outros serviços (client credentials) e On-Behalf-Of.</summary>
/// <example>
/// <code>
/// "Security": {
///   "EntraId": {
///     "Client": {
///       "TenantId": "&lt;tenant-id&gt;",
///       "ClientId": "&lt;client-id-desta-aplicacao&gt;",
///       "Credential": { "Type": "ManagedIdentityFederation" }
///     }
///   }
/// }
/// </code>
/// </example>
public sealed class EntraIdClientOptions
{
    /// <summary>Instância (nuvem). Ver <see cref="EntraIdAppOptions.Instance"/>.</summary>
    public string Instance { get; set; } = "https://login.microsoftonline.com/";

    /// <summary>Tenant da aplicação (GUID). Obrigatório, exceto com <see cref="EntraIdCredentialType.ManagedIdentity"/>.</summary>
    public string? TenantId { get; set; }

    /// <summary>Client id da app registration (GUID). Obrigatório, exceto com <see cref="EntraIdCredentialType.ManagedIdentity"/> e <see cref="EntraIdCredentialType.Developer"/>.</summary>
    public string? ClientId { get; set; }

    /// <summary>Credencial da aplicação.</summary>
    public EntraIdCredentialOptions Credential { get; set; } = new();
}
