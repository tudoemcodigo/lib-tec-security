# 📝 Changelog

Todas as mudanças relevantes do **TEC.Security** são registradas aqui. O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/). Os quatro pacotes saem sempre com a mesma versão.

## [0.0.1] - 2026-10-23

Versão inaugural oficial da suíte de segurança e autorização do ecossistema TEC.

### ✨ Adicionado

#### 🛡️ TEC.Security (núcleo agnóstico)
- **Identidade normalizada:** `ISecurityUser` (Scoped, implementando também `ICurrentUser` e `ICurrentTenant` do TEC.Core) com id, tipo, tenant, papéis, escopos e permissões normalizados.
- **`SecurityIdentityFactory`:** sanitização de nomes de exibição (anti-injeção Bidi/Unicode, limite de caracteres), resolução segura de tenants, descarte de claims reservados `tec_*` e falha fechada contra stores indisponíveis.
- **API Keys de Alta Entropia:** `ApiKeyGenerator` (256 bits, prefixo `tec_` para detecção de vazamentos) e `ApiKeyValidator` (tempo constante com hash dummy para mitigar timing attacks, `CryptographicOperations.ZeroMemory`).
- **Chamadas de Serviço (M2M) e Blindagem SSRF:** `AccessTokenHandler` com restrição estrita de portas em `AllowedHosts` (SEC-14), prevenindo desvios para portas não autorizadas no mesmo host.
- **Tolerância a Falhas e Resiliência:** `SecurityCircuitBreaker` com Polly integrado e métricas dedicadas.
- **Workers e Background Jobs:** `ISecurityContext` com identidade `System` e execução segura via `RunAs`.

#### 🌐 TEC.Security.AspNetCore
- **Seleção Dinâmica de Provedor:** esquema `TEC` que roteia por requisição (Bearer token JWT, header de API Key, query param em hubs SignalR e cookies web).
- **Hardening Criptográfico Estrito:** `JwtHardening` proibindo algoritmos fracos (`none`, `HS256` externo com confusão de chave pública), forçando HTTPS para JWKS, tolerância de relógio reduzida (30 s) e bloqueio de adulterações em `TokenValidationParameters`.
- **Autorização Fechada por Padrão:** atributo `[TecAuthorize]`, Minimal APIs via `.RequireTecAuthorization()`, auditoria de negações e respostas 401/403 padronizadas com o `ApiResponse` do TEC.Core.
- **Login Web Seguro:** Authorization Code + PKCE, cookies com prefixo `__Host-`, SameSite estrito e revalidação periódica de permissões e tenant ativo.

#### 🌐 TEC.Security.OpenIdConnect (Provedor Universal Agnóstico)
- **Agnóstico e Multi-Cloud:** suporte completo a Keycloak, Auth0, Okta, Microsoft Entra ID (OIDC), Google Identity e AWS Cognito.
- **Mapeamento Inteligente de Papéis:** extração automática de claims padrão `roles` e estruturas aninhadas do Keycloak (`realm_access.roles` e `resource_access`).
- **M2M Client Credentials (RFC 6749):** obtenção de tokens de serviço com cache inteligente em memória, renovação antecipada (`RefreshMargin`) e circuit breaker.
- **Segredos Seguros:** integração nativa com o `TEC.Vault` para leitura de client secrets e client assertions.

#### 🧪 TEC.Security.Testing
- **Emissor de Tokens em Memória:** `TestTokenIssuer` gerando pares de chaves RSA em memória para suítes de testes de integração, bloqueado fora de ambientes `Development`, `Testing` e `Test`.

[0.0.1]: https://github.com/tudoemcodigo/lib-tec-security
