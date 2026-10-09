# 📝 Changelog

Todas as mudanças relevantes do **TEC.Security** são registradas aqui. O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa [Versionamento Semântico](https://semver.org/lang/pt-BR/). Enquanto a versão for `0.x`, mudanças incompatíveis podem ocorrer em versões MINOR. Os quatro pacotes saem sempre com a mesma versão.

## [0.1.0] - 2026-10-09

### ✨ Adicionado

#### 🛡️ TEC.Security

- **Circuit breaker para provedores de identidade** (`SecurityCircuitBreaker`, `SecurityCircuitBreakerOptions`, `SecurityCircuitOpenException`, com `Polly.Core`). `CachingAccessTokenProvider` aceita um circuito em volta de `AcquireTokenAsync`: aberto, a renovação falha na hora e o token atual ainda válido continua em uso. Na chamada de teste (meia-abertura), cancelamento conta como falha. Métrica `security.circuit.state_changes` e eventos 3123–3125.

#### 🪪 TEC.Security.EntraId

- **Resiliência em `EntraIdClientOptions.Resilience`** (`EntraId:Client:Resilience`): retentativa do On-Behalf-Of só em falha de rede, tempo limite, 408, 429 e 5xx, com backoff exponencial, jitter e `Retry-After` limitado por `MaxRetryDelay`; erros OAuth (`invalid_grant`, `interaction_required`...) nunca são repetidos. A client assertion é gerada a cada tentativa.
- Circuit breaker ligado por padrão para os tokens da aplicação e para o On-Behalf-Of (este conta só falhas transitórias: o `invalid_grant` de um usuário não derruba os outros).

### 🔁 Alterado

- Tempo limite do `HttpClient` do On-Behalf-Of agora é repetido e, esgotadas as tentativas, vira `SecurityTokenAcquisitionException` (antes escapava como `OperationCanceledException`).
- Nova dependência: `Polly.Core` 8.8.0 (sem dependências próprias em net8/net10, compatível com Native AOT).

## [0.0.1] - 2026-10-08

Primeira versão. Nada foi publicado ainda: esta entrada descreve o que os pacotes oferecem.

### ✨ Adicionado

#### 🛡️ TEC.Security (núcleo, sem ASP.NET Core)

- **Identidade normalizada:** `ISecurityUser` (Scoped, também registrado como `ICurrentUser` do TEC.Core e `ICurrentTenant`) com id, tipo, tenant, papéis, escopos e permissões, iguais para qualquer provedor; claims `tec_*` (`TecClaimTypes`) com marca de normalização; `SecurityUser` para ler um principal.
- **`SecurityIdentityFactory`:** converte a `ExternalIdentity` de qualquer provedor no principal normalizado: descarta os `tec_*` do provedor, resolve o tenant só pelo cadastro, valida formatos (`SecurityRules`), limita a 512 papéis/escopos/permissões, sanea o nome de exibição (recusa controles bidirecionais, separadores de linha/parágrafo e surrogates soltos; até 256 caracteres sem partir pares) e falha fechada se o `IPermissionStore` falhar; `RevalidateAsync` para sessões longas.
- **Tenants:** `ITenantRegistry` com o cadastro `Security:Tenants` (`ConfigurationTenantRegistry`), vínculo por provedor, recarga sem reinício com recusa de versões inválidas, ids externos só ASCII; `RequireTenant`; `UseTenantRegistry<T>()` para outras fontes.
- **Permissões:** `IPermissionStore` com mapeamento papel → permissões em `Security:Permissions` (global e por tenant), `RolesAsPermissions`; `UsePermissionStore<T>()` com cache privado de até 50.000 entradas, chave de tamanho fixo (SHA-256 em Base64Url), uma consulta por chave (`SingleFlight` do TEC.Core, cancelamento individual), `null` tratado como lista vazia e resultados acima do limite fora do cache.
- **Workers:** `ISecurityContext` com `CreateSystemPrincipalAsync` (identidade `System` que nenhum token produz) e `RunAs`, com `AsyncLocal` por instância.
- **API keys:** `ApiKeyGenerator` (256 bits, prefixo `tec_`, Base64Url estrito e canônico do TEC.Core) e `ApiKeyValidator` (SHA-256, tempo constante inclusive para id desconhecido, validade obrigatória, hash não canônico recusado na validação das opções, cadastro inválido relido no máximo 1×/s mantendo a última versão válida).
- **Tokens de serviço:** `AccessTokenHandler` (token só para `AllowedHosts` com HTTPS) e `CachingAccessTokenProvider` (cache por conjunto de escopos, renovação 5 min antes, uma obtenção por vez, token atual mantido se a renovação falhar e ele ainda valer mais de 30 s, até 1024 conjuntos de escopos, `ObjectDisposedException` após `Dispose`); `SecurityTokenAcquisitionException` derivada de `AppException` (`SEGURANCA_PROVEDOR_INDISPONIVEL`, HTTP 502).
- **`SecurityBuilder`:** `UsePermissionStore`/`UseTenantRegistry` chamados duas vezes lançam `InvalidOperationException`; `AddTecSecurity` repetido também.
- **Erros e telemetria:** `SecurityErrors` com as mensagens padrão do TEC.Core (`ApiResponse.DefaultMessages`); `SecurityDiagnostics` (Meter e ActivitySource `TEC.Security`, sem dados pessoais); eventos de log 3000–3199 sem segredos.

#### 🌐 TEC.Security.AspNetCore

- `AddAspNetCore()`: esquema `TEC` que escolhe o provedor por requisição (emissor, header de API key, cookie) e recusa credenciais não reconhecidas (`TEC.None`); `DefaultPolicy` e `FallbackPolicy` exigindo identidade normalizada.
- `JwtHardening`: padrões endurecidos e lista de **permissão** de algoritmos (RS\*, PS\*, ES\* em nomes curtos e URIs; HMAC só com `allowSymmetricKeys`, nunca nos esquemas do TEC.Security), `AlgorithmValidator` personalizado recusado; controles obrigatórios conferidos por `IValidateOptions` depois de toda configuração e materializados na subida.
- `[TecAuthorize]` (policy codificada válida em controllers, Minimal APIs, gRPC, hubs SignalR e Blazor), `RequireTecAuthorization`, `RequirePermission`; conferência dos endpoints na subida; auditoria de negações (o caminho sem endpoint vai para o log só como tamanho + HMAC).
- Respostas 401/403 com o `ApiResponse` do TEC.Core, `no-store` e `traceId`.
- `AddApiKeys()` (só header e HTTPS), token na query só nos hubs configurados (`HubPaths`), `MaxTokenLength`.
- Login web: `AddWebLoginProvider` com Authorization Code + PKCE, cookie `__Host-`, revalidação de tenant e permissões, duração máxima absoluta, 401 para chamadas de API; `SaveTokens`, `MapInboundClaims` e userinfo impedem a subida; `MapTecWebLogin` com `returnUrl` local e logout por POST da mesma origem.
- `AddJwtBearerProvider`, `JwtProviderDefinition`, `WebLoginDefinition` e `SecuritySchemes` para pacotes de provedor.

#### 🪪 TEC.Security.EntraId

- `AddEntraIdApi`: RS256, emissor exato por tenant, multi-tenant pelo cadastro (com recarga), ID token recusado, `AllowedClientApplications`, tokens v1 e de aplicação configuráveis; várias app registrations na mesma aplicação.
- `AddEntraIdWebLogin` com credencial da aplicação sem segredo na configuração.
- `AddEntraIdClient`, `AddEntraIdAccessToken` (client credentials) e `AddEntraIdOnBehalfOf` (uma troca por usuário + escopos em andamento via `SingleFlight`, cache privado; endpoint de token lido com teto de 64 KB, validade pelo `TimeProvider` e `expires_in` entre 1 s e 24 h; erros só com o código OAuth validado).
- Credenciais: identidade gerenciada federada, Workload Identity (token federado lido com `BoundedFileReader`, até 16 KB), certificado do TEC.Vault com client assertion PS256 assinada no cofre, segredo do TEC.Vault (cache imutável, uma leitura por vez), identidade gerenciada e Developer (só Development); nuvens pública, US Gov e China.

#### 🧪 TEC.Security.Testing

- `TestTokenIssuer(issuer, audience, TimeProvider? time = null)` com chave RSA em memória e validação de emissor/audiência; `CreateToken` lança `ObjectDisposedException` após `Dispose`.
- `AddTestJwt`, com as mesmas regras endurecidas e bloqueado fora de Development, Testing e Test.

#### ⚙️ Qualidade

- Alvos `net8.0` e `net10.0`, compatíveis com Native AOT e trimming; analisadores de segurança e auditoria de pacotes como erro.
- Testes TUnit + FsCheck (unitários, ponta a ponta, fuzzing, DoS, vazamento, tempo constante), integração com Entra ID e Key Vault reais (variáveis `TEC_TESTES_*`), carga (`TEC.Security.LoadTests`: `Carga-CI` e `Carga-Pesada`, parâmetros `TEC_CARGA_*`) e benchmarks (`TEC.Security.Benchmarks`), com categorias centralizadas em `TestCategories`.
- Workflows `ci.yml`, `release.yml` e `performance.yml` sobre o tec-workflows.

[0.0.1]: https://github.com/tudoemcodigo/lib-tec-security
