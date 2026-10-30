# 📝 Changelog

Todas as mudanças relevantes do **TEC.Security** são registradas aqui. O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/). Os quatro pacotes saem sempre com a mesma versão.

## [0.0.1] - 2026-10-30

Versão inaugural oficial da suíte de segurança e autorização do ecossistema TEC. Os pacotes trazem só `lib/net10.0`, sem versões condicionais por TFM nem polyfills.

### ✨ Adicionado

#### 🛡️ TEC.Security (núcleo agnóstico)
- **Identidade normalizada:** `ISecurityUser` (Scoped, implementando também `ICurrentUser` e `ICurrentTenant` do TEC.Core) com id, tipo, tenant, papéis, escopos e permissões normalizados.
- **`SecurityIdentityFactory`:** sanitização de nomes de exibição (anti-injeção Bidi/Unicode, limite de caracteres), resolução segura de tenants, descarte de claims reservados `tec_*` e falha fechada contra stores indisponíveis.
- **Prova da normalização:** é o tipo criado pelo `SecurityIdentityFactory`, não um claim. Um principal montado à mão (ou vindo de outro esquema) com todos os claims `tec_*` é anônimo, e os claims `tec_*` de uma identidade normalizada não podem ser incluídos nem removidos depois da criação (`InvalidOperationException`).
- **`TecClaimTypes.MultiTenant`** (`tec_multi_tenant`): o indicador multi-tenant viaja na identidade normalizada.
- **API Keys de Alta Entropia:** `ApiKeyGenerator` (256 bits, prefixo `tec_` para detecção de vazamentos) e `ApiKeyValidator` (tempo constante com hash dummy para mitigar timing attacks, `CryptographicOperations.ZeroMemory`). O limitador do log 3110 varre as entradas no máximo uma vez por intervalo, mesmo com o cadastro cheio e ids inventados.
- **Chamadas de Serviço (M2M) e Blindagem SSRF:** `AccessTokenHandler` com restrição estrita de portas em `AllowedHosts` (SEC-14), prevenindo desvios para portas não autorizadas no mesmo host.
- **Tolerância a Falhas e Resiliência:** `SecurityCircuitBreaker` com Polly integrado e métricas dedicadas.
- **Workers e Background Jobs:** `ISecurityContext` com identidade `System` e execução segura via `RunAs`.
- **Logs sem dados do token:** o motivo de recusa por tenant traz só o tamanho e um identificador do valor do claim. O aviso 3403 (`RolesAsPermissions = true` com identidade multi-tenant) sai uma vez por processo.

#### 🌐 TEC.Security.AspNetCore
- **Seleção Dinâmica de Provedor:** esquema `TEC` que roteia por requisição (Bearer token JWT, header de API Key, query param em hubs SignalR e cookies web).
- **Hardening Criptográfico Estrito:** `JwtHardening` proibindo algoritmos fracos (`none`, `HS256` externo com confusão de chave pública), exigindo HTTPS para metadados e JWKS (exceto `Authority` em loopback), tolerância de relógio reduzida (30 s) e bloqueio de adulterações em `TokenValidationParameters`.
- **Delegates de evento fechados:** `Success()` ou principal definido em `OnMessageReceived` e `OnAuthenticationFailed` (JWT), a troca do token ou do principal em `OnTokenValidated` e os equivalentes do login web (`OnMessageReceived`, `OnAuthorizationCodeReceived`, `OnTokenResponseReceived`, `OnAuthenticationFailed`, `OnTicketReceived`) recusam a autenticação. Gravar no cookie de sessão uma identidade que não veio do `SecurityIdentityFactory` lança `InvalidOperationException`.
- **Autorização Fechada por Padrão:** atributo `[TecAuthorize]`, Minimal APIs via `.RequireTecAuthorization()`, auditoria de negações e respostas 401/403 padronizadas com o `ApiResponse` do TEC.Core.
- **Login Web Seguro:** Authorization Code + PKCE, cookie com prefixo `__Host-`, `SameSite=Lax` e revalidação periódica de permissões e tenant ativo, que preserva o indicador multi-tenant e o `RolesAsPermissions`.

#### 🌐 TEC.Security.OpenIdConnect (Provedor Universal Agnóstico)
- **Agnóstico e Multi-Cloud:** suporte completo a Keycloak, Auth0, Okta, Microsoft Entra ID (OIDC), Google Identity e AWS Cognito.
- **Tipo da identidade (`Kind`) por regras do esquema** (`OpenIdConnectApiOptions.Kind`, `OpenIdConnectKindOptions` e `OpenIdConnectUnresolvedKind`): regras `claim=valor` (com `*` e prefixo) para aplicação e para usuário, `sub` igual ao client, regra do `scp` do Entra ID (automática para as authorities do Entra) e o que fazer com o token não reconhecido, também lidas da seção de configuração (`Kind:*`). O token que nenhuma regra reconhece é **recusado** (401), e o `preferred_username` (editável no IdP) não decide nada. Contas de serviço do Keycloak precisam de `Kind:ApplicationClaims` com `client_id=*`, e o Auth0 de `Kind:Unresolved = User`; o Entra ID já sai certo, com ou sem `idtyp`. Receitas em [Provedor OpenID Connect](docs/provedor-openid-connect.md).
- **Mapeamento Inteligente de Papéis:** extração automática de claims padrão `roles` e estruturas aninhadas do Keycloak (`realm_access.roles` e `resource_access`). No login web, `resource_access` só traz os papéis do próprio `ClientId`.
- **M2M Client Credentials (RFC 6749):** obtenção de tokens de serviço com cache inteligente em memória, renovação antecipada (`RefreshMargin`) e circuit breaker. `AddOpenIdConnectClient` valida as opções na subida (`ValidateOnStart`) e só pode ser chamado uma vez: sem segredo, `ClientSecretName` sem `ISecretReader`, `PrivateKeyJwt` ou HTTP fora de loopback impedem a aplicação de subir.
- **Endpoint de token endurecido:** o `HttpClient` não segue redirecionamentos, não guarda cookies e recicla as conexões a cada 2 minutos (acompanha troca de DNS do IdP, mesmo vivendo no Singleton); o tempo limite vale até a leitura completa do corpo; a resposta tem teto de 256 KB; `expires_in` inválido falha fechado, ausente vale 60 segundos e acima de 24 horas o cache considera 24 horas. `AddOpenIdConnectAccessToken` passa o logger ao `AccessTokenHandler` (o bloqueio de destino aparece no log 3121).
- **Segredos Seguros:** o client secret é lido do `TEC.Vault` (`ClientSecretName`). No login web, o segredo é conferido na subida e lido do cofre de novo a cada login (troca do código e PAR), sem ficar nas opções: a rotação no cofre vale sem reiniciar. `PrivateKeyJwt` (client assertion) está declarado em `OpenIdConnectM2MAuthType`, mas não é suportado: o provedor lança `NotSupportedException`.

#### 🧪 TEC.Security.Testing
- **Emissor de Tokens em Memória:** `TestTokenIssuer` gerando pares de chaves RSA em memória para suítes de testes de integração, bloqueado fora de ambientes `Development`, `Testing` e `Test`.

### 🛠️ Manutenção
- Lock files só com `net10.0`. O projeto de testes não tem `Integration/TestSettings.cs` nem os pacotes que só ele usava (`TEC.Vault.AzureKeyVault`, `TEC.Vault.InMemory`, `Microsoft.Extensions.Configuration.Json` e `Microsoft.Extensions.Configuration.UserSecrets`).
- `LeakageTests` estável: a chave alterada não sai mais em Base64Url não canônico.
- XML docs alinhadas ao comportamento real: `OpenIdConnectClientOptions.TokenEndpoint`, `ValidIssuers`, `MultiTenant`, os remarks de `ITenantRegistry`, `OpenIdConnectM2MAuthType.PrivateKeyJwt`, sem referências a pacotes e métodos que não existem (`TEC.Security.EntraId`, `AddEntraId*`).

[0.0.1]: https://github.com/tudoemcodigo/lib-tec-security/releases/tag/v0.0.1
