# ADR 0008: Provedor de Identidade Plugável e Provedor OpenID Connect Agnóstico

## Status
Aprovado (registro retroativo)

## Data
2026-10-23

## Contexto
Os sistemas do ecossistema TEC usam provedores diferentes (Keycloak, Auth0, Okta, Entra ID, Google, Cognito), às vezes mais de um ao mesmo tempo (usuários internos e parceiros, mais API keys e login web). Cada `AddJwtBearer` configurado à mão repete o risco de alguém desligar um controle, e o núcleo não pode depender de um SDK de IdP nem do ASP.NET Core (workers e mensageria também o usam).

## Decisão
- **Pacotes em camadas**: `TEC.Security` (núcleo, sem ASP.NET Core nem SDK de IdP), `TEC.Security.AspNetCore` (esquemas, autorização e respostas), `TEC.Security.OpenIdConnect` (provedor) e `TEC.Security.Testing` (emissor de tokens de teste). Os pacotes saem sempre com a mesma versão.
- **Ponto de extensão para provedores**: o provedor só informa como reconhecer o token e como convertê-lo em `ExternalIdentity`: [`JwtProviderDefinition`](../../TEC.Security.AspNetCore/Authentication/JwtProviderDefinition.cs) (`AddJwtBearerProvider`) para tokens bearer e [`WebLoginDefinition`](../../TEC.Security.AspNetCore/Authentication/WebLoginDefinition.cs) (`AddWebLoginProvider`) para login web. A validação endurecida, a normalização, os eventos e a conferência dos controles ficam com o TEC.Security ([ADR 0002](0002-autorizacao-fechada-por-padrao-e-controles-conferidos-na-subida.md)).
- **Vários provedores ao mesmo tempo**: o policy scheme `TEC` ([`TecSchemeSelector`](../../TEC.Security.AspNetCore/Authentication/TecSchemeSelector.cs)) escolhe o esquema por requisição (token bearer pelo `CanHandle` do provedor, header de API key, `access_token` da query só em `HubPaths`, cookie do login web). O token é lido **sem validação** só para escolher; quem valida é o esquema escolhido, e o que não é reconhecido cai no `TEC.None`, que recusa.
- **Provedor agnóstico**: o [`TEC.Security.OpenIdConnect`](../../TEC.Security.OpenIdConnect/OpenIdConnectExtensions.cs) implementa um único provedor (`Provider = "OpenIdConnect"`) sobre os padrões abertos: API (`AddOpenIdConnectApi`), login web com Authorization Code + PKCE (`AddOpenIdConnectWebLogin`) e client credentials (`AddOpenIdConnectClient`), com mapeamento de papéis do Keycloak (`realm_access`, `resource_access`) e dos claims padrão. O segredo do cliente vem do TEC.Vault.
- **Microsoft Entra ID** é atendido por esse provedor (tokens v2). A revisão técnica de 2026-10-19 cita um pacote `TEC.Security.EntraId`, que não faz parte do código atual; o repositório não registra o motivo da troca ([provedor-entra-id.md](../provedor-entra-id.md)).
- **Provedor de teste**: `AddTestJwt` aceita tokens do [`TestTokenIssuer`](../../TEC.Security.Testing/TestTokenIssuer.cs) com as mesmas regras endurecidas e impede a subida fora de Development, Testing e Test.

## Consequências
### Positivas
- Um provedor novo é um conjunto pequeno de código (reconhecer, converter) e herda as garantias de segurança.
- A aplicação troca ou soma IdPs sem mudar o código de negócio.
- O núcleo funciona em workers sem ASP.NET Core.

### Neutras / Negativas
- Recursos específicos de um IdP não existem no provedor agnóstico: hoje o Entra ID não tem On-Behalf-Of, credenciais por certificado/identidade gerenciada, nem validação de `azp`/`idtyp` para autorizar, e `OpenIdConnectM2MAuthType.PrivateKeyJwt` está reservado sem implementação (com ele, o `AddOpenIdConnectClient` impede a subida) ([provedor-entra-id.md](../provedor-entra-id.md#o-que-não-existe)).
- O emissor aceito é a `Authority` ou, com `MultiTenant`, um item de `ValidIssuers`; os emissores extras usam o JWKS da `Authority`. IdPs com chaves distintas por emissor (um realm do Keycloak por tenant) exigem um esquema por emissor.
- O tipo da identidade vem de regras por esquema e o token não reconhecido é recusado ([ADR 0009](0009-tipo-da-identidade-por-regras-com-recusa-do-token-nao-reconhecido.md)); cada IdP pode exigir uma regra própria (ex.: contas de serviço do Keycloak).
