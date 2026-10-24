[🏠 TEC.Security](../README.md) › [📚 Documentação](README.md) › 🔍 Revisão técnica

# 🔍 Revisão técnica

> Revisão de segurança, código, organização e documentação dos quatro pacotes do TEC.Security, com cada achado conferido
> no fonte (`arquivo:linha`), o cenário concreto de impacto e a correção sugerida.

## 📑 Sumário

- [🎯 Escopo e método](#-escopo-e-método)
- [🧪 Build e testes](#-build-e-testes)
- [📊 Resumo dos achados](#-resumo-dos-achados)
- [📌 Status dos achados](#-status-dos-achados)
- [🔎 Achados](#-achados)
- [🛠️ Correções aplicadas — 2026-10-19](#️-correções-aplicadas--2026-10-19)
- [✅ Pontos fortes conferidos](#-pontos-fortes-conferidos)
- [🚀 Melhorias sugeridas](#-melhorias-sugeridas)
- [📝 Ajustes na documentação](#-ajustes-na-documentação)

---

## 🎯 Escopo e método

| Item | Valor |
|---|---|
| Data | 2026-10-19 |
| Commit analisado | `e07991e Retry e circuit breaker nas chamadas ao Entra ID com Polly.Core (0.1.0) (#3)` |
| Versão | `0.1.0` (`Directory.Build.props`) |
| Pacotes | `TEC.Security`, `TEC.Security.AspNetCore`, `TEC.Security.EntraId`, `TEC.Security.Testing` |
| Também lidos | `TEC.Security.Tests`, `TEC.Security.LoadTests`, `TEC.Security.Benchmarks`, `build/`, `.github/workflows/`, `docs/`, READMEs; TEC.Observability (só para conferir `ConfigureHttpClientDefaults`) |
| Foco | JWT/Entra ID (emissor, audiência, assinatura, algoritmos, validade, multi-tenant, JWKS), API keys, identidade e permissões, autorização, tenants, chamadas entre serviços (client credentials, OBO, `AllowedHosts`), workers, erros, logs e resiliência |

Severidades: **Crítica** (exploração direta, quebra de autenticação/isolamento), **Alta** (exploração plausível ou falha
séria de disponibilidade), **Média** (falha real com condição específica), **Baixa** (defeito menor, endurecimento ou
manutenção), **Info** (observação, sem defeito). Achados que não se confirmaram na releitura do fonte foram descartados.
As linhas citadas (`arquivo:linha`) são as do commit analisado; nos `.md` corrigidos por esta revisão elas podem ter
mudado.

---

## 🧪 Build e testes

| Passo | Comando | Resultado |
|---|---|---|
| Build (modo pacote, padrão) | `dotnet build TEC.Security.slnx -c Release` | ❌ `NU1301` 401 no feed `tec-interno` (sem credencial do GitHub Packages nesta máquina); não é defeito do código |
| Build (modo local) | `dotnet build TEC.Security.slnx -c Release -p:TecUseLocalProjects=true` | ✅ 0 avisos, 0 erros (SDK 10.0.401, os dois TFMs, todos os projetos) |
| Unitários net10.0 | `dotnet test --project TEC.Security.Tests ... -- --treenode-filter "/*/*/*/*[Category!=Integracao]"` | ✅ 204/204 aprovados (6,5 s) |
| Unitários net8.0 | idem | ⚠️ não executados: a máquina só tem o runtime ASP.NET Core 10.0.12 (`Microsoft.AspNetCore.App 8.0.0` ausente) |
| Integração, carga, `Seguranca-Pesada` | — | Não executados (fora do escopo pedido) |

Descoberta de testes (`--list-tests`, net10.0): 209 no total = 204 unitários + 2 `Integracao` + 3 `Seguranca-Pesada`.

---

## 📊 Resumo dos achados

| ID | Severidade | Categoria | Local | Resumo |
|---|---|---|---|---|
| SEC-01 | Média | Bug / resiliência | `TEC.Security/Tokens/CachingAccessTokenProvider.cs:116`, `TEC.Security/Resilience/SecurityCircuitBreaker.cs:49` | Tempo limite do provedor chega como `OperationCanceledException`: ignora o token ainda válido, não vira `SecurityTokenAcquisitionException` e conta como **sucesso** no circuit breaker |
| SEC-02 | Média | Bug / desempenho | `TEC.Security/Tokens/CachingAccessTokenProvider.cs:161` | Token com validade ≤ 5 min nunca é reaproveitado: toda chamada vai ao provedor, serializada pela trava do conjunto de escopos (o exemplo Keycloak da doc cai nisso) |
| SEC-03 | Média | Segurança / lógica | `TEC.Security/ApiKeys/ApiKeyValidator.cs:143`, `TEC.Security/Tenants/ConfigurationTenantRegistry.cs:66` | Recarga com qualquer erro de validação descarta **também** as revogações nela (chave `Enabled: false`, tenant desativado): a versão anterior, com a chave ativa, continua valendo |
| SEC-04 | Baixa | Build / dependências | `TEC.Security.EntraId/packages.lock.json:364` | No net8.0, `Microsoft.IdentityModel.Abstractions` 8.14.0 convive com `Tokens`/`JsonWebTokens`/`Logging` 7.7.3 (versões misturadas, não suportado pela Microsoft) |
| SEC-05 | Baixa | Disponibilidade | `TEC.Security.AspNetCore/SecurityBuilderWebLoginExtensions.cs:142` | Falha passageira do `IPermissionStore` na revalidação **encerra** a sessão web (sign-out), em vez de recusar só a requisição |
| SEC-06 | Baixa | Lógica | `TEC.Security/Permissions/ConfigurationPermissionStore.cs:23` | `Permissions:Tenants:{id}` diferencia maiúsculas, o cadastro de tenants não: chave com grafia diferente é ignorada em silêncio |
| SEC-07 | Baixa | Segurança (padrão) | `TEC.Security/Configuration/SecurityOptions.cs:30`, `TEC.Security.EntraId/EntraIdExtensions.cs:86` | `RolesAsPermissions = true` por padrão também em API multi-tenant; só um aviso de log (3403) |
| SEC-08 | Baixa | Endurecimento | `TEC.Security.AspNetCore/Authentication/JwtHardening.cs:111` | `Enforce` não confere `IssuerSigningKeyResolver`/`IssuerSigningKeyValidator`, `TokenHandlers` nem o teto de tamanho no handler |
| SEC-09 | Baixa | Endurecimento | `TEC.Security.EntraId/EntraIdExtensions.cs:88` | Multi-tenant sem validação do emissor da chave de assinatura (equivalente ao `EnableAadSigningKeyIssuerValidation`) |
| SEC-10 | Baixa | API / fechado por padrão | `TEC.Security.AspNetCore/SecurityBuilderAspNetCoreExtensions.cs:78`, `:86` | `FallbackPolicy` e o `IAuthorizationPolicyProvider` podem ser trocados depois pela aplicação sem nenhuma conferência (o resto dos controles é validado na subida) |
| SEC-11 | Baixa | Resiliência | `TEC.Security.EntraId/EntraIdExtensions.cs:223`, `TEC.Security.EntraId/Internal/EntraIdTokenEndpoint.cs:136` | OBO sem orçamento total de tempo: 3 tentativas × 30 s + esperas de até 10 s seguram a requisição do usuário por ~110 s |
| SEC-12 | Baixa | Testes | `TEC.Security.EntraId/EntraIdOnBehalfOfHandler.cs` | Handler OBO sem teste direto (pré-condições, cache, `SingleFlight`, `AllowedHosts`) |
| SEC-13 | Baixa | Observabilidade | `TEC.Security/ApiKeys/ApiKeyValidator.cs:152` | Um log `Warning` 3110 por tentativa recusada, sem amostragem: inundação de log sem rate limiting na frente |
| SEC-14 | Info | Segurança | `TEC.Security/Tokens/AccessTokenHandler.cs:37` | `AllowedHosts` confere só o host: qualquer porta do host recebe o token |
| SEC-15 | Info | Funcionalidade | `TEC.Security.EntraId/EntraIdOnBehalfOfHandler.cs:117` | OBO só lê o header `Authorization`: conexões SignalR autenticadas por `access_token` na query não conseguem OBO |
| SEC-16 | Info | Resiliência | `TEC.Security.EntraId/Internal/EntraIdClientCredential.cs:107` | Client credentials usa retentativa e tempo limite padrão do Azure.Identity (rede 100 s por tentativa), fora do `EntraIdResilienceOptions` |
| SEC-17 | Info | Dependências | `Directory.Packages.props` | O núcleo leva `Microsoft.Extensions.*` 10.0.12 também para consumidores net8.0 |
| SEC-18 | Baixa | Testes / CI | `.github/workflows/ci.yml:39`, `TEC.Security.LoadTests/TestCategories.cs:6` | Testes de concorrência `Carga-CI` (segundos) não rodam em PR nem no release, só no `performance.yml` manual; os comentários das categorias dizem o contrário |
| DOC-01 | Baixa | Documentação | `docs/chamadas-entre-servicos.md:161` | Exemplo de provedor próprio com token de 5 min, que nunca é reaproveitado (SEC-02) |
| DOC-02 | Baixa | Documentação | `docs/api-keys.md:116`, `docs/tenants.md:37` | "Revogar/desativar vale na próxima requisição" sem a ressalva da recarga inválida (SEC-03) |
| DOC-03 | Info | Documentação | `README.md:14`, `:113`, `:118`, READMEs dos pacotes, `docs/desenvolvimento.md:156` | Versão `0.0.1`; o código está em `0.1.0` |
| DOC-04 | Info | Documentação | `README.md:264`, `docs/testes.md:46`, `:173` | "181 testes por TFM" (são 204) e tabela de suítes sem `ResilienceTests` |
| DOC-05 | Info | Documentação | `README.md:64` | Dependências do núcleo sem `Polly.Core` |
| DOC-06 | Info | Documentação | `docs/provedor-entra-id.md:57` | "Sem `scp` → `Application`" simplifica demais a regra (`idtyp=app` ou `sub == oid`, senão recusa) |
| DOC-07 | Info | Documentação | `docs/configuracao.md:279` | "`HubPaths` vazio" sugere que a lista vazia (padrão) é recusada |

Contagem: **Crítica 0 · Alta 0 · Média 3 · Baixa 13 · Info 9** (SEC: 3 Média, 11 Baixa, 4 Info; DOC: 2 Baixa, 5 Info).

## 📌 Status dos achados

Situação em 2026-10-19, branch `fix/revisao-tecnica-2026-10-19` (detalhes em
[Correções aplicadas](#-correções-aplicadas--2026-10-19)).

| ID | Status | Arquivos alterados | Teste de regressão |
|---|---|---|---|
| SEC-01 | ✅ Corrigido | `Tokens/CachingAccessTokenProvider.cs`, `Resilience/SecurityCircuitBreaker.cs`, `Claims/SecurityIdentityFactory.cs`, `EntraIdOnBehalfOfHandler.cs`, `EntraIdExtensions.cs` (troca do código) | `ResilienceTests.Timeout_without_caller_cancellation_counts_as_failure`, `Provider_timeout_keeps_current_token_and_becomes_acquisition_failure`, `Caller_cancellation_*`; `TechnicalReviewRegressionTests.Permission_store_timeout_*` |
| SEC-02 | ✅ Corrigido | `CachingAccessTokenProvider.cs` (`RefreshMargin`: 1/4 da validade, até 5 min), `EntraIdOnBehalfOfHandler.cs` | `ResilienceTests.Short_lived_token_is_reused_until_a_quarter_of_its_lifetime_remains` |
| SEC-03 | ✅ Corrigido (breaking) | `ApiKeys/ApiKeyValidator.cs`, `Tenants/ConfigurationTenantRegistry.cs`, `DependencyInjection/ServiceCollectionExtensions.cs`, `Internal/SecurityLog.cs` | `TechnicalReviewRegressionTests.Api_key_revocation_applies_*`, `Api_key_removal_applies_*`, `Invalid_reload_without_unvalidated_reader_refuses_every_key`; `TenantRegistryTests.Invalid_reload_*` |
| SEC-04 | ✅ Corrigido no `Directory.Packages.props`; ⏳ lock files pendentes | `Directory.Packages.props` | Build/testes no modo local (`packages.local.lock.json` sem 7.x). Os `packages.lock.json` versionados **não** foram regenerados: o restore no modo pacote dá 401 no `tec-interno` (ver abaixo) |
| SEC-05 | ✅ Corrigido | `SecurityBuilderWebLoginExtensions.cs`, `Internal/AspNetCoreSecurityLog.cs` | `TechnicalReviewRegressionTests.Transient_permission_store_failure_rejects_request_but_keeps_web_session`, `Provider_rule_rejection_still_ends_web_session` |
| SEC-06 | ✅ Corrigido | `Configuration/SecurityOptions.cs` (`OrdinalIgnoreCase`), `ServiceCollectionExtensions.cs` (aviso 3102 na subida) | `TechnicalReviewRegressionTests.Tenant_permissions_match_the_catalog_ignoring_case_*` |
| SEC-07 | ✅ Corrigido (breaking) | `SecurityOptions.cs` (`bool?`), `SecurityIdentityFactory.cs`, `EntraIdExtensions.cs`, `Internal/EntraIdLog.cs` | `EntraIdApiTests.Multi_tenant_app_roles_are_not_permissions_unless_explicitly_enabled` |
| SEC-08 | ✅ Corrigido | `Authentication/JwtHardening.cs`, `SecurityOptionsValidators.cs` | `TechnicalReviewRegressionTests.Weakening_hooks_prevent_startup` (8 casos) |
| SEC-09 | ✅ Corrigido | `Internal/EntraIdSigningKeyIssuer.cs` (novo), `EntraIdExtensions.cs`, `JwtProviderDefinition.cs`, `SecuritySchemes.cs`, `SecurityBuilderAspNetCoreExtensions.cs` | `TechnicalReviewRegressionTests.Signing_key_pinned_to_another_tenant_is_rejected` |
| SEC-10 | ✅ Corrigido | `SecurityOptionsValidators.cs`, `SecurityBuilderAspNetCoreExtensions.cs` | `TechnicalReviewRegressionTests.Removing_the_fallback_policy_*`, `Custom_policy_provider_*` (2) |
| SEC-11 | ✅ Corrigido | `EntraIdOptions.cs` (`AttemptTimeout`, `TotalTimeout`), `Internal/EntraIdTokenEndpoint.cs`, `EntraIdExtensions.cs` | `ResilienceTests.On_behalf_of_total_timeout_*`, `Out_of_range_timeouts_are_rejected` |
| SEC-12 | ✅ Corrigido | — (só testes) | `OnBehalfOfHandlerTests` (7 testes) |
| SEC-13 | ✅ Corrigido | `ApiKeyValidator.cs` (`RejectionLogLimiter`), `SecurityLog.cs` | `TechnicalReviewRegressionTests.Repeated_api_key_rejections_*`, `Rejection_log_limiter_memory_is_bounded_*` |
| SEC-14 | ⏸️ Não corrigido | — | Info: aceitar `host:porta` muda o formato de `AllowedHosts` (decisão de API) |
| SEC-15 | ⏸️ Não corrigido | — | Info: ler `access_token` da query no OBO amplia o uso do token da query; exige decisão |
| SEC-16 | ⏸️ Não corrigido | — | Info: expor `Retry`/`NetworkTimeout` do Azure.Identity é API nova, fora do escopo |
| SEC-17 | ⏸️ Não corrigido | — | Info: condicionar `Microsoft.Extensions.*` por TFM afeta todos os componentes (decisão do tec-workflows) |
| SEC-18 | ✅ Corrigido | `.github/workflows/ci.yml`, `release.yml`, `TestCategories.cs` (2), `ConcurrencyTests.cs` (regra nova do SEC-03) | `Carga-CI` executado: 8/8 |
| DOC-01, DOC-02 | ✅ Corrigido | `chamadas-entre-servicos.md`, `api-keys.md`, `tenants.md`: ressalvas trocadas pelo comportamento novo | — |
| DOC-03 a DOC-07 | ✅ Corrigido (na revisão) | Versão agora `0.2.0` | — |
| tec-workflows I2 | ⏸️ Não aplicado | — | `.gitignore` fora do escopo (ordem: tec-workflows → tag `v1` → componentes) |
| tec-workflows I3 | ⏳ Bloqueado | — | Subir `TEC.Core`/`TEC.Vault*` exige restore do `tec-interno` (401 nesta máquina) |
| tec-workflows I4 | ⏳ Bloqueado | — | `PackageValidationBaselineVersion` = `0.1.0` baixa o pacote do `tec-interno` no `pack` (401); aplicar com credencial |

---

## 🔎 Achados

### SEC-01 · Média · Tempo limite do provedor tratado como cancelamento do chamador

**Problema.** A base `CachingAccessTokenProvider` e o `SecurityCircuitBreaker` tratam toda `OperationCanceledException`
como cancelamento pedido pelo chamador. Só que tempo limite de `HttpClient` (`TaskCanceledException`) e o tempo limite de
rede do Azure.Core também chegam como `OperationCanceledException`, com o token do chamador **não** cancelado.

**Evidência.**

```csharp
// TEC.Security/Tokens/CachingAccessTokenProvider.cs:116
catch (Exception exception) when (exception is not OperationCanceledException)
{   // ... fallback para o token atual (:123), log 3120 e SecurityTokenAcquisitionException (:132)
```

```csharp
// TEC.Security/Resilience/SecurityCircuitBreaker.cs:49-50
ShouldHandle = args => ValueTask.FromResult(args.Outcome.Exception is { } ex
    && (ex is OperationCanceledException ? _state.CircuitState == CircuitState.HalfOpen : isFailure(ex))),
```

O teste `ResilienceTests.cs:231` (`Cancellation_while_closed_does_not_open_circuit`) fixa esse comportamento usando
`default` como token, ou seja, sem cancelamento do chamador. O `EntraIdTokenEndpoint` (OBO) já faz a distinção certa
(`EntraIdTokenEndpoint.cs:106`, `when (!cancellationToken.IsCancellationRequested)`), mas o caminho de client credentials e
qualquer provedor próprio herdado de `CachingAccessTokenProvider` não fazem.

**Impacto.** Numa degradação do Entra ID (ou do IdP de um provedor próprio) que se manifeste como lentidão, cenário comum:
(1) o token ainda válido em cache **não** é usado (a regra dos 30 s, log 3122, é pulada); (2) o chamador recebe
`TaskCanceledException` crua em vez de `SecurityTokenAcquisitionException` (HTTP 502 padronizado), e o TEC.Cqrs a trata
como cancelamento; (3) sem log 3120 nem `error.type` na métrica; (4) cada tempo limite conta como **sucesso** para o
Polly, então o circuito nunca abre e cada requisição espera o tempo limite inteiro.

**Correção sugerida.** Distinguir pelo token do chamador nos dois pontos e ajustar o teste:

```csharp
// CachingAccessTokenProvider.GetTokenAsync
catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)

// SecurityCircuitBreaker: o contexto do Polly traz o token do chamador
ShouldHandle = args => ValueTask.FromResult(args.Outcome.Exception is { } ex && (ex is OperationCanceledException
    ? !args.Context.CancellationToken.IsCancellationRequested || _state.CircuitState == CircuitState.HalfOpen
    : isFailure(ex))),
```

O mesmo vale para `SecurityIdentityFactory.cs:142` (um `IPermissionStore` que estoura tempo limite via `HttpClient` hoje
vira exceção não tratada/500 em vez de `ProviderFailure` com log 3003).

### SEC-02 · Média · Token com validade de até 5 minutos nunca vem do cache

**Problema.** `IsFresh` exige mais de `RefreshBefore` (5 min, fixo) de validade restante. Um token emitido com validade
≤ 5 min já nasce "vencido" para o cache.

**Evidência.**

```csharp
// TEC.Security/Tokens/CachingAccessTokenProvider.cs:161
private bool IsFresh(AccessToken? token) => token is not null && token.ExpiresOn - _time.GetUtcNow() > RefreshBefore;
```

O exemplo de provedor próprio em [chamadas-entre-servicos.md](chamadas-entre-servicos.md#provedor-de-token-próprio)
(linha 161) devolve `AddMinutes(5)`, e 5 minutos é o *Access Token Lifespan* padrão do Keycloak, o IdP do exemplo.

**Impacto.** Toda chamada HTTP de saída faz uma ida ao IdP, e como a obtenção roda sob `entry.Lock` (`:97`), as chamadas
do mesmo conjunto de escopos ficam **serializadas** atrás dela: vazão limitada à latência do IdP e carga desnecessária no
IdP. Não há aviso em log.

**Correção sugerida.** Antecedência proporcional à validade, com o mesmo teto atual:

```csharp
private bool IsFresh(AccessToken? token)
{
    if (token is null) return false;
    var remaining = token.ExpiresOn - _time.GetUtcNow();
    var lifetime = token.ExpiresOn - token.IssuedAt;          // guardar a emissão no Entry (ou no AccessToken)
    var margin = TimeSpan.FromTicks(Math.Min(RefreshBefore.Ticks, lifetime.Ticks / 4));
    return remaining > margin;
}
```

E corrigir o exemplo da documentação (ver DOC-01 em [Ajustes na documentação](#-ajustes-na-documentação)).

### SEC-03 · Média · Recarga inválida descarta revogações

**Problema.** O cadastro de API keys e o de tenants são aplicados "tudo ou nada": se a nova versão tiver **qualquer** erro
(um hash colado errado em outra chave, um `TenantId` fora do formato, um id externo duplicado), a versão inteira é
ignorada e a anterior continua valendo, inclusive na parte que revogava acesso.

**Evidência.**

```csharp
// TEC.Security/ApiKeys/ApiKeyValidator.cs:143-149
catch (OptionsValidationException exception)
{
    ...
    return _lastValid;   // versão anterior, com a chave que acabou de ser desativada
}
```

```csharp
// TEC.Security/Tenants/ConfigurationTenantRegistry.cs:66-71
var snapshot = Build(options, out string? error);
if (snapshot is null) { SecurityLog.TenantReloadRejected(...); return; }   // tenant desativado continua ativo
```

A documentação promete o contrário para API keys: "Revogar na hora: `"Enabled": false` (ou remover a entrada). Vale na
próxima requisição." (`api-keys.md:116`).

**Impacto.** Resposta a incidente: o operador desativa a chave vazada `erp-contoso` e, na mesma edição, cadastra
`erp-contoso-2027` com o hash truncado. A recarga é recusada (log 3111 **uma única vez**, nível Error), a chave vazada
segue aceita e o operador acredita que revogou. O mesmo com `Enabled: false` num tenant junto de outro erro no cadastro.

**Correção sugerida.** Separar "inválido" de "revogação": aplicar as remoções e desativações mesmo quando o restante da
versão é recusado (interseção conservadora), ou validar por entrada e descartar só a chave/tenant inválido.

```csharp
// API keys: a versão efetiva nunca tem uma chave mais permissiva que a da versão nova
static ApiKeyOptions Merge(ApiKeyOptions lastValid, ApiKeyOptions candidate) // candidate = bind cru, sem validação
{
    var merged = new ApiKeyOptions { HeaderName = lastValid.HeaderName };
    foreach (var (id, old) in lastValid.Keys)
    {
        if (!candidate.Keys.TryGetValue(id, out var current) || current is null) continue;  // removida: revogada
        merged.Keys[id] = current.Enabled && current.Hash == old.Hash ? old : Disabled(old); // desativada/trocada: fecha
    }
    return merged;
}
```

E documentar o comportamento em `api-keys.md` e `tenants.md` (ver DOC-02).

### SEC-04 · Baixa · `Microsoft.IdentityModel.*` em versões misturadas no net8.0

**Problema.** No net8.0, o JwtBearer 8.0.31 traz `Microsoft.IdentityModel.Tokens`/`JsonWebTokens`/`Logging`/`Protocols`
7.7.3, e o Azure.Identity → MSAL 4.83.1 sobe `Microsoft.IdentityModel.Abstractions` para 8.14.0.

**Evidência.** `TEC.Security.EntraId/packages.lock.json:364-379` (`Abstractions` `"resolved": "8.14.0"`,
`JsonWebTokens`/`Logging` `"resolved": "7.7.3"`). No net10.0 está tudo em 8.19.2.

**Impacto.** A Microsoft só suporta o conjunto `Microsoft.IdentityModel.*` na mesma versão; versões misturadas já causaram
`MissingMethodException`/`TypeLoadException` em produção em outras bibliotecas. Os testes passam hoje, mas uma atualização
do Azure.Identity pode quebrar a validação de token só no net8.0, e só em runtime. Além disso, os dois TFMs validam tokens
com majors diferentes da IdentityModel (7.x × 8.x).

**Correção sugerida.** Fixar o conjunto no `Directory.Packages.props` (o pinning transitivo já está ligado), na mesma versão
nos dois TFMs:

```xml
<ItemGroup>
  <PackageVersion Include="Microsoft.IdentityModel.Abstractions" Version="8.19.2" />
  <PackageVersion Include="Microsoft.IdentityModel.JsonWebTokens" Version="8.19.2" />
  <PackageVersion Include="Microsoft.IdentityModel.Logging" Version="8.19.2" />
  <PackageVersion Include="Microsoft.IdentityModel.Protocols.OpenIdConnect" Version="8.19.2" />
  <PackageVersion Include="Microsoft.IdentityModel.Tokens" Version="8.19.2" />
</ItemGroup>
```

### SEC-05 · Baixa · Falha passageira do `IPermissionStore` derruba a sessão web

**Problema.** Na revalidação periódica do cookie, qualquer falha de `RevalidateAsync` encerra a sessão com
`RejectPrincipal` + `SignOutAsync`, inclusive `SecurityErrors.ProviderFailure()` (exceção do store).

**Evidência.** `SecurityIdentityFactory.cs:142-146` converte exceção do store em `ProviderFailure`;
`SecurityBuilderWebLoginExtensions.cs:144-153` trata qualquer falha como `"revalidação recusada"` e, em `:157-163`,
apaga o cookie.

**Impacto.** Um soluço de alguns segundos no banco de permissões (TEC.ORM) desloga todos os usuários web cuja
revalidação cair nessa janela; eles passam pelo Entra ID de novo (carga e atrito), quando bastaria negar a requisição.

**Correção sugerida.** Diferenciar o código do erro: em `SecurityErrors.ProviderFailureCode`, `RejectPrincipal()` só para
a requisição atual (sem `SignOutAsync` e sem atualizar `ValidatedAtKey`), mantendo o encerramento para tenant inativo,
identidade inválida e regra do provedor.

### SEC-06 · Baixa · Permissões por tenant diferenciam maiúsculas

**Problema.** O cadastro de tenants busca ignorando maiúsculas (`ConfigurationTenantRegistry.cs:86`, `OrdinalIgnoreCase`) e
devolve o id canônico; o mapeamento `Security:Permissions:Tenants` usa `StringComparer.Ordinal`
(`SecurityOptions.cs:101`) e é consultado com esse id (`ConfigurationPermissionStore.cs:23`).

**Impacto.** `"Tenants": { "Contoso": {...} }` no cadastro e `"Permissions": { "Tenants": { "contoso": {...} } }` faz as
permissões do tenant sumirem sem erro nem log (falha fechada, mas difícil de diagnosticar). Também não há validação de que
as chaves de `Permissions:Tenants` existem no cadastro.

**Correção sugerida.** `StringComparer.OrdinalIgnoreCase` em `PermissionOptions.Tenants` e um `IValidateOptions<PermissionOptions>`
que avise (log) chaves de tenant desconhecidas e valores fora de `SecurityRules.IsValidName`.

### SEC-07 · Baixa · `RolesAsPermissions = true` como padrão em multi-tenant

**Problema.** Em API multi-tenant, o administrador de qualquer tenant cliente liberado pode atribuir **qualquer** app role
da API aos próprios usuários; com o padrão `RolesAsPermissions = true`, o nome do papel vira permissão direto.

**Evidência.** `SecurityOptions.cs:30` (`= true`); `EntraIdExtensions.cs:86-87` só registra o aviso 3403.

**Impacto.** Um `[TecAuthorize(Permissions = "admin:global")]` atendido por app role atribuído pelo admin de um cliente.
O risco está documentado (checklist de `seguranca.md`), mas o padrão continua inseguro justamente na configuração mais
exposta.

**Correção sugerida.** Com `MultiTenant = true` e `RolesAsPermissions` não definido explicitamente, tratar como `false`
(ou falhar a subida exigindo a escolha explícita), mantendo o aviso para quem optar por `true`.

### SEC-08 · Baixa · `JwtHardening.Enforce` não cobre todos os ganchos de validação

**Problema.** `Enforce` recusa `SignatureValidator`, `LifetimeValidator` e `AlgorithmValidator` personalizados, mas não
confere `IssuerSigningKeyResolver`, `IssuerSigningKeyValidator`, `TokenReader`, a lista `TokenHandlers` (substituída por
um handler sem `MaximumTokenSizeInBytes`) nem `TokenDecryptionKeys`.

**Evidência.** `TEC.Security.AspNetCore/Authentication/JwtHardening.cs:111-140`.

**Impacto.** Um `PostConfigure` da aplicação (ou um provedor novo, ver [novo-provedor.md](novo-provedor.md)) pode passar a
aceitar chaves fora do JWKS do emissor (`IssuerSigningKeyResolver` que devolve chave de outra origem) sem que a subida
acuse, contrariando a promessa de "controles que nenhuma configuração consegue desligar".

**Correção sugerida.**

```csharp
Require(p.IssuerSigningKeyResolver is null && p.IssuerSigningKeyResolverUsingConfiguration is null,
    "IssuerSigningKeyResolver personalizado não é permitido (chaves só do JWKS do emissor).");
Require(p.TokenReader is null, "TokenReader personalizado não é permitido.");
Require(options.TokenHandlers.Count == 1 && options.TokenHandlers[0] is JsonWebTokenHandler { MapInboundClaims: false } h
    && h.MaximumTokenSizeInBytes <= 256 * 1024, "TokenHandlers não pode ser substituído.");
```

### SEC-09 · Baixa · Multi-tenant sem validação do emissor da chave de assinatura

**Problema.** Com `MultiTenant = true`, as chaves vêm do JWKS de `organizations` e o emissor é conferido pelo
`EntraIdTenantPolicy.ValidateIssuer`, mas não há a conferência de que a chave usada pertence ao emissor do token
(propriedade `issuer` das chaves do JWKS do Entra), que o Microsoft.Identity.Web aplica com
`EnableAadSigningKeyIssuerValidation()`.

**Evidência.** `EntraIdExtensions.cs:88-91` (só `Authority`, `ValidAudiences`, `IssuerValidator` e `ValidAlgorithms`).

**Impacto.** Defesa em profundidade recomendada pela Microsoft para apps multi-tenant; o risco prático com o JWKS global é
baixo, mas é a camada que impede um token assinado por chave de outro contexto (ex.: chave de outra nuvem/tenant com
chaves próprias) de ser aceito só porque o `iss` bate.

**Correção sugerida.** Adicionar um `IssuerSigningKeyValidator` interno (e liberá-lo no `Enforce`) que compare o
`issuer` da `JsonWebKey` (com `{tenantid}` substituído pelo `tid`) ao `iss` do token.

### SEC-10 · Baixa · Política de fallback sem conferência na subida

**Problema.** Ao contrário de JwtBearer/OIDC/cookie (validados por `SecurityOptionsValidators`), as opções de autorização
não são conferidas: um `services.AddAuthorization(o => o.FallbackPolicy = null)` posterior torna públicos todos os
endpoints sem atributo; e `RemoveAll<IAuthorizationPolicyProvider>()` remove em silêncio um provedor de policies que a
aplicação tenha registrado antes.

**Evidência.** `SecurityBuilderAspNetCoreExtensions.cs:75-80` e `:86-87`.

**Correção sugerida.** `IValidateOptions<AuthorizationOptions>` exigindo que `FallbackPolicy` e `DefaultPolicy` contenham
`TecAuthenticatedRequirement`, e falha explícita (ou composição) se já houver um `IAuthorizationPolicyProvider` diferente do
padrão.

### SEC-11 · Baixa · OBO sem orçamento total de tempo

**Problema.** O `HttpClient` do endpoint de token tem 30 s por tentativa (`EntraIdExtensions.cs:223`) e o OBO repete até 2
vezes com esperas de até `MaxRetryDelay` (10 s) (`EntraIdTokenEndpoint.cs:136-148`). Não há tempo limite total.

**Impacto.** Com o Entra ID lento (sem 5xx), uma requisição do usuário que dependa de OBO pode ficar ~110 s presa, e
várias requisições simultâneas do mesmo usuário ficam presas na mesma `SingleFlight`.

**Correção sugerida.** Uma estratégia `AddTimeout` do Polly por fora da retentativa (ex.: `Resilience.TotalTimeout`, padrão
30 s) e tempo limite por tentativa menor (ex.: 10 s).

### SEC-12 · Baixa · `EntraIdOnBehalfOfHandler` sem teste direto

**Problema.** Os testes cobrem `EntraIdTokenEndpoint` e o circuito do OBO (`ResilienceTests.cs`), mas nenhum exercita o
handler: recusa fora de `AllowedHosts`, recusa de token de aplicação/API key/cookie, chave de cache por hash do token,
reaproveitamento do cache e a `SingleFlight`.

**Correção sugerida.** Testes com `DefaultHttpContext` + principal normalizado e um `HttpMessageHandler` falso para o
endpoint de token (o construtor já recebe tudo por parâmetro).

### SEC-13 · Baixa · Log de auditoria por tentativa de API key, sem amostragem

**Problema.** Cada chave recusada gera um `Warning` 3110 (`ApiKeyValidator.cs:152-157`); sem rate limiting na frente (o
componente não tem, por decisão documentada), um cliente consegue gerar milhares de linhas de log por segundo.

**Correção sugerida.** Manter a métrica por tentativa e limitar o log por id/motivo (ex.: um log por `keyId` + motivo a
cada minuto, com contagem agregada), como já é feito para o log 3111.

### SEC-14 · Info · `AllowedHosts` não restringe porta

`AccessTokenHandlerOptions.TryGetDestinationHost` (`AccessTokenHandler.cs:48-59`) devolve só `IdnHost`: com
`estoque.contoso.com` na lista, `https://estoque.contoso.com:8443/` também recebe o token. Considere aceitar entradas
`host:porta` (e exigir a porta padrão quando não informada).

### SEC-15 · Info · OBO não funciona para hubs autenticados por query string

`EntraIdOnBehalfOfHandler.TryGetBearer` (`:117-126`) só lê o header `Authorization`; requisições de hub que se
autenticaram por `access_token` (`TecJwtBearerEvents.cs:24`) recebem `HttpRequestException`. Documentar a limitação ou
ler o token pelo mesmo caminho do seletor.

### SEC-16 · Info · Client credentials fora do `EntraIdResilienceOptions`

`EntraIdClientCredential.CreateTokenCredential` (`:107-128`) não define `Retry`/`NetworkTimeout` nas opções do
Azure.Identity: valem os padrões (3 retentativas, 100 s de rede por tentativa) e, enquanto isso, as chamadas do mesmo
conjunto de escopos esperam na trava do `CachingAccessTokenProvider`. A doc diz isso ("a retentativa é a do
Azure.Identity"), mas não há como ajustar; expor `NetworkTimeout`/`MaxRetries` também para esse fluxo.

### SEC-17 · Info · `Microsoft.Extensions.*` 10.x no net8.0

O núcleo referencia `Microsoft.Extensions.Caching.Memory`/`Http`/`Options...` 10.0.12 nos dois TFMs
(`Directory.Packages.props`), o que obriga consumidores net8.0 a subir esses pacotes para 10.x. É suportado, mas vale
registrar no README (ou condicionar as versões por TFM como já é feito com os pacotes do ASP.NET Core).

### SEC-18 · Baixa · Testes de concorrência fora do CI

**Problema.** A categoria `Carga-CI` (concorrência nos singletons e fumaça de carga HTTP, segundos) só é selecionada pelo
`performance.yml` (`:58`), de disparo manual. O `ci.yml` (`:39-40`) e o `release.yml` rodam só `[Category!=Integracao]`
de `TEC.Security.Tests` e `[Category=Integracao]`; `TEC.Security.LoadTests` não entra. Os comentários de
`TEC.Security.LoadTests/TestCategories.cs:6` ("rodam no PR") e `:9`/`TEC.Security.Tests/TestCategories.cs:14` ("rodam no
release") não correspondem aos workflows.

**Impacto.** Regressões de concorrência em `CachingAccessTokenProvider`, `CachingPermissionStore`, `ApiKeyValidator` e
`CurrentSecurityUser` (justamente onde estão SEC-01/SEC-02) passam pelo PR sem teste.

**Correção sugerida.** Incluir `TEC.Security.LoadTests /*/*/*/*[Category=Carga-CI]` no `unit-tests` do `ci.yml` (ou um
input próprio no workflow reutilizável) e alinhar os comentários.

### DOC-01 a DOC-07 · Documentação

Divergências entre documentação e código, conferidas nos dois lados e **já corrigidas** nesta revisão (lista em
[Ajustes na documentação](#-ajustes-na-documentação)):

| ID | Doc dizia | Código |
|---|---|---|
| DOC-01 | Exemplo `KeycloakTokenProvider` com `AddMinutes(5)` | `IsFresh` exige mais de 5 min restantes (`CachingAccessTokenProvider.cs:161`) |
| DOC-02 | "Revogar na hora... Vale na próxima requisição" / "desativar vale na próxima requisição" | Recarga inválida mantém a versão anterior (`ApiKeyValidator.cs:143-149`, `ConfigurationTenantRegistry.cs:66-71`) |
| DOC-03 | Versão `0.0.1` (badge, `dotnet add package`, "Versão atual", `desenvolvimento.md`) | `Directory.Build.props:6` `<Version>0.1.0</Version>`; `CHANGELOG.md:5` `[0.1.0]` |
| DOC-04 | "181 por TFM"; suítes sem `ResilienceTests` | 204 unitários (209 descobertos − 2 `Integracao` − 3 `Seguranca-Pesada`); `ResilienceTests.cs` com 16 métodos |
| DOC-05 | Núcleo depende de "`TEC.Core`, `Microsoft.Extensions.*`" | `TEC.Security/TEC.Security.csproj:24` `<PackageReference Include="Polly.Core" />` |
| DOC-06 | "com `scp` → `User`, sem `scp` → `Application`" | `EntraIdIdentity.cs:47-55`: `idtyp=app` prevalece; sem `scp` exige `idtyp=app` ou `sub == oid`, senão recusa |
| DOC-07 | "`HubPaths` vazio ou `/`" → `InvalidOperationException` | `SecurityAspNetCoreOptions.cs:47`: recusa só **entrada** vazia ou `/`; a lista vazia é o padrão |

Conferidos sem divergência: eventos de log (3001–3125, 3201–3207, 3401–3403), métricas e motivos (inclusive `session`,
`remote`, `not_normalized`), códigos de erro e status HTTP, limites e padrões de `seguranca.md`/`configuracao.md`, nomes de
testes citados em `seguranca.md`, variáveis `TEC_TESTES_*`/`TEC_CARGA_*` e os três workflows. Links relativos e âncoras
entre os docs estão íntegros.

## 🛠️ Correções aplicadas — 2026-10-19

Versão `0.1.0` → **`0.2.0`** (MINOR: há mudanças incompatíveis, permitidas em `0.x`; ver `CHANGELOG.md`).

**Decisões de design**

- **SEC-03, por entrada (falha fechada):** em vez de mesclar com a versão anterior, a recarga com erro aplica a versão nova
  validando cada chave/tenant; entradas com erro ficam recusadas/inativas. Motivo: é a única regra em que nenhuma edição
  consegue manter ativo o que ela mesma revogou, e não depende de comparar com a versão anterior (que pode ter sido
  carregada há meses). Custo: um erro numa chave existente a desliga até a correção (log 3111/3101 avisa). A leitura sem
  validação usa as mesmas `IConfigureOptions`/`IPostConfigureOptions` do `AddTecSecurity` (`OptionsFactory` sem validadores).
- **SEC-07, padrão seguro (breaking) em vez de só aviso:** `RolesAsPermissions` vira `bool?`; não definido = `true`, mas
  `false` quando há provedor multi-tenant (via `PostConfigure` registrado por `AddEntraIdApi`/`AddEntraIdWebLogin`). Vale
  para a aplicação inteira, como a opção. `true` explícito mantém o aviso 3403.
- **SEC-05:** falha passageira do store recusa só a requisição (sem `SignOutAsync` e sem atualizar a revalidação); uma
  navegação nesse instante ainda é desafiada pelo login, mas o cookie não é apagado.
- **SEC-09:** só em multi-tenant; chave sem `issuer` no JWKS é aceita (como no Microsoft.Identity.Web).

**Build e testes** (SDK 10.0.401, modo local `-p:TecUseLocalProjects=true`)

| Passo | Resultado |
|---|---|
| `dotnet build TEC.Security.slnx -c Release -p:TecUseLocalProjects=true` | ✅ 0 avisos, 0 erros (net8.0 e net10.0) |
| Unitários net10.0 (`TEC.Security.Tests`, `[Category!=Integracao]`) | ✅ 245/245 (antes 204) |
| `TEC.Security.LoadTests` `[Category=Carga-CI]` net10.0 | ✅ 8/8 |
| Unitários net8.0 | ⚠️ não executados: runtime `Microsoft.AspNetCore.App 8.0` ausente nesta máquina |
| Integração, `Carga-Pesada`, `Seguranca-Pesada` | Não executados |
| Modo pacote (`packages.lock.json` versionados) | ⏳ Bloqueado: 401 no `tec-interno`. Com o token configurado, rode `dotnet restore TEC.Security.slnx --force-evaluate` e commite os 7 `packages.lock.json` (o SEC-04 muda as versões de `Microsoft.IdentityModel.*` no net8.0; sem isso o CI em modo travado falha) |

---

## ✅ Pontos fortes conferidos

Itens verificados no fonte e **sem** achado, para orientar revisões futuras:

- **JWT:** `ValidAlgorithms` por lista de permissão (`none` e HMAC recusados, inclusive nas grafias URI), RS256 fixo no Entra
  ID, `TryAllIssuerSigningKeys = false`, `ClockSkew` 30 s (máx. 2 min), `RequireSignedTokens`/`RequireExpirationTime`/
  `RequireAudience`, `MapInboundClaims`/`SaveToken` desligados, `RequireHttpsMetadata`, recarga do JWKS limitada a 5 min,
  `IncludeErrorDetails` só em Development; tudo conferido de novo depois de qualquer `PostConfigure`.
- **Entra ID:** emissor exato por tenant e por versão (`EntraIdTenantPolicy.ValidateIssuer`), `tid` conferido contra a lista
  estática e o cadastro **a cada token**, `Instance` restrita às nuvens oficiais (sem caminho/porta/query), ID token
  recusado como access token (`nonce` e ausência de `azp`/`appid`), token de aplicação só com `idtyp=app` ou `sub == oid`,
  `AllowedClientApplications`.
- **Claims:** claims `tec_*` do provedor sempre descartados; marca `tec_normalized`; limites de 512 itens e formatos ASCII;
  nome de exibição sem controles bidirecionais.
- **Tenants:** tenant sempre do cadastro, nunca de header/query/claim; nenhuma troca de tenant por header no código.
- **API keys:** 256 bits, SHA-256 + `FixedTimeEquals` com hash fictício para id desconhecido, formato canônico estrito,
  `ExpiresOn` obrigatório, só header, HTTPS fora de Development.
- **Autorização:** `FallbackPolicy` fechada, `[TecAuthorize]` com `[AllowAnonymous]` recusado na subida, `context.Fail` nas
  negações, escopo negado para token de aplicação.
- **Chamadas entre serviços:** `AllowedHosts` + HTTPS obrigatórios, token do usuário nunca repassado (só trocado por OBO),
  OBO no tenant do usuário, resposta do endpoint de token com teto de 64 KB e erro OAuth reduzido a código validado, client
  assertion nova por tentativa.
- **Login web:** code + PKCE, `form_post`, nonce/state, cookie `__Host-` HttpOnly/Secure/Lax, duração absoluta, tenant
  conferido a cada requisição, `returnUrl` só local, logout só POST e mesma origem.
- **Erros e logs:** 401/403 genéricos (`ApiResponse` do TEC.Core, `no-store`), motivo só no log; logs nunca levam token,
  segredo ou mensagem de exceção de validação de token.
- **Testes:** suíte adversarial (fuzzing com FsCheck, DoS, vazamento, tempo constante) e regressões nomeadas por achado.

---

## 🚀 Melhorias sugeridas

Em ordem de prioridade:

| # | Melhoria | Por quê |
|:-:|---|---|
| 1 | Corrigir SEC-01 e SEC-03 antes da 1.0 | São os dois pontos em que o comportamento real contraria a promessa (fallback/circuito; revogação "na hora") |
| 2 | Fixar `Microsoft.IdentityModel.*` numa versão única (SEC-04) e rodar os unitários net8.0 em toda máquina de dev (doc de desenvolvimento) | Evita quebra só em runtime e só num TFM |
| 3 | Revogação explícita de API key por lista de bloqueio (`Security:ApiKeys:Revoked: [ "erp-contoso" ]`) aplicada mesmo com o resto do cadastro inválido | Caminho de incidente simples e à prova de erro de edição |
| 4 | `IApiKeyStore` (como `IPermissionStore`/`ITenantRegistry`) para guardar chaves no banco/cofre, com `LastUsedAt` | Rotação sem deploy de configuração e detecção de chaves sem uso |
| 5 | Rate limiting opcional embutido para falhas de autenticação (`AddTecAuthenticationRateLimiter`: partição por IP + id de chave) | O risco "sem rate limiting" aparece em três docs; um padrão pronto reduz configuração esquecida |
| 6 | Validação do emissor da chave de assinatura no Entra multi-tenant (SEC-09) e opção `RequireTokenType` (`typ`) por provedor | Defesa em profundidade alinhada ao Microsoft.Identity.Web |
| 7 | Checagem de "token revogado" plugável (`ITokenRevocationCheck`, ex.: CAE/`xms_cc` ou lista por `uti`) | Reduz a janela do risco residual "token roubado vale até expirar" |
| 8 | Orçamento de tempo total e `AddTimeout` no OBO e no client credentials (SEC-11, SEC-16) | Latência previsível sob degradação do IdP |
| 9 | Health check `AddTecSecurityHealthChecks()` (circuito aberto, JWKS desatualizado, cadastro rejeitado na última recarga) | Hoje esses estados só aparecem em log/métrica |
| 10 | Analisador Roslyn que acuse endpoint com `[Authorize]` padrão ou `[AllowAnonymous]` sem justificativa | Leva o "fechado por padrão" para a compilação |

---

## 📝 Ajustes na documentação

Corrigidos diretamente nesta revisão (só fatos; nenhum código, teste ou csproj alterado):

| Arquivo | Ajuste |
|---|---|
| `README.md` | Badge, `dotnet add package` e "Versão atual" para `0.1.0`; "204 testes unitários por TFM"; `Polly.Core` nas dependências do núcleo |
| `TEC.Security/README.md`, `TEC.Security.AspNetCore/README.md`, `TEC.Security.EntraId/README.md`, `TEC.Security.Testing/README.md` | `--version 0.1.0` |
| `docs/desenvolvimento.md` | `Version` do `Directory.Build.props` = `0.1.0`; rodapé com link para esta revisão |
| `docs/testes.md` | "204 por TFM"; linha da suíte `ResilienceTests` |
| `docs/provedor-entra-id.md` | Regra completa de `User` × `Application` |
| `docs/configuracao.md` | `HubPaths`: só entrada vazia ou `/` é recusada |
| `docs/api-keys.md`, `docs/tenants.md` | Ressalva da recarga inválida que mantém a versão anterior (SEC-03) |
| `docs/chamadas-entre-servicos.md` | Exemplo de provedor próprio com `expires_in` e o aviso do cache para tokens de até 5 min (SEC-02) |
| `docs/README.md` | Tema 16 (esta revisão) na tabela e no mapa |

Pendentes (dependem de decisão ou de mudança de código), situação em 2026-10-19: os itens sobre SEC-01, SEC-03 e SEC-18
abaixo foram resolvidos pelas correções (ressalvas trocadas pelo comportamento novo, comentários alinhados); resta confirmar
a publicação da versão no README.

- Quando SEC-01, SEC-02 e SEC-03 forem corrigidos, remover as ressalvas acrescentadas em `api-keys.md`, `tenants.md` e
  `chamadas-entre-servicos.md` e registrar no `CHANGELOG.md`.
- `seguranca.md` (riscos residuais): acrescentar "recarga inválida mantém revogações antigas" enquanto SEC-03 existir.
- `chamadas-entre-servicos.md`: dizer que o circuito e o fallback do token atual **não** cobrem tempo limite no client
  credentials enquanto SEC-01 existir.
- Comentários de `TEC.Security.Tests/TestCategories.cs:14` e `TEC.Security.LoadTests/TestCategories.cs:6`/`:9` (código,
  não alterado aqui): alinhar com os workflows (SEC-18).
- "Versão atual: 0.1.0 (ainda não publicada)" no `README.md`: confirmar se a 0.1.0 já está no feed e ajustar o texto.

---
⬅️ [💻 Desenvolvimento local](desenvolvimento.md) · [📚 Índice](README.md)
