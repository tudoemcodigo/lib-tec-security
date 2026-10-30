[🏠 TEC.Security](../README.md) › [📚 Documentação](README.md) › 🧪 Testes

# 🧪 Testes

> Como testar a **sua** API protegida com o `TEC.Security.Testing` e como o próprio componente é testado: categorias,
> suítes de segurança, carga, benchmarks e as variáveis `TEC_CARGA_*`.

## 📑 Sumário

- [🎯 Visão geral](#-visão-geral)
- [🚀 Uso](#-uso)
  - [Testando a sua API](#testando-a-sua-api)
  - [Rodar localmente](#rodar-localmente)
  - [Suítes](#suítes)
  - [Testes de segurança](#testes-de-segurança)
  - [Integração com provedor real](#integração-com-provedor-real)
  - [Carga](#carga)
  - [Benchmarks](#benchmarks)
  - [No CI](#no-ci)
  - [Escrevendo novos testes](#escrevendo-novos-testes)
- [⚙️ Opções](#️-opções)
- [❌ Erros](#-erros)
- [🛡️ Segurança](#️-segurança)
- [❓ Perguntas frequentes](#-perguntas-frequentes)

---

## 🎯 Visão geral

```mermaid
flowchart LR
    T["dotnet test"] --> U["TEC.Security.Tests<br/>Category != Integracao<br/><sub>unitários, ponta a ponta, fuzzing, DoS, vazamento</sub>"]
    T --> SP["TEC.Security.Tests<br/>Seguranca-Pesada [Explicit]"]
    T --> L["TEC.Security.LoadTests<br/>Carga-CI · Carga-Pesada [Explicit]"]
    U --> R["net10.0 · net10.0 sem ICU"]
    B["dotnet run TEC.Security.Benchmarks"] --> BD["BenchmarkDotNet"]
```

| Projeto | Categoria | Conteúdo | Quantidade |
|---|---|---|---:|
| `TEC.Security.Tests` | *(sem categoria)* | Unitários, ponta a ponta (TestServer), regressão, fuzzing (FsCheck), DoS, vazamento, tempo constante rápido | 309 |
| `TEC.Security.Tests` | `Integracao` | Reservada para provedor real; ainda sem testes | 0 |
| `TEC.Security.Tests` | `Seguranca-Pesada` | Canais laterais de tempo (teste t de Welch) | 3 |
| `TEC.Security.LoadTests` | `Carga-CI` | Concorrência nos singletons e fumaça de carga HTTP (segundos) | 8 |
| `TEC.Security.LoadTests` | `Carga-Pesada` | Volume, soak, carga sustentada e inundação (minutos) | 6 |
| `TEC.Security.Benchmarks` | — | BenchmarkDotNet do caminho quente (sob demanda) | — |

- Framework: **TUnit** sobre o Microsoft.Testing.Platform (`global.json` → `"test": { "runner": "Microsoft.Testing.Platform" }`),
  com **FsCheck** para as propriedades. Projetos `Exe`, `net10.0`, fora dos pacotes.
- As categorias ficam numa classe `TestCategories` por projeto: `Integration = "Integracao"` e
  `SecurityHeavy = "Seguranca-Pesada"` em `TEC.Security.Tests`; `LoadCi = "Carga-CI"` e `LoadHeavy = "Carga-Pesada"` em
  `TEC.Security.LoadTests`. A seleção é **sempre por categoria**; os pesados têm `[Explicit]` e só rodam quando a categoria
  é pedida.
- Nomes de teste em inglês, descrevendo o comportamento (`Injected_tec_perm_claim_does_not_grant_permission`).

---

## 🚀 Uso

### Testando a sua API

O pacote **TEC.Security.Testing** emite tokens JWT assinados (RS256) por um par de chaves RSA gerado na memória do processo
de teste, validados com as **mesmas** regras endurecidas dos provedores reais. Nenhuma chave vai para o disco, e o
provedor de teste impede a aplicação de subir fora de Development, Testing e Test.

```csharp
// Program.cs: o emissor de teste só existe quando os testes o definem
using TEC.Security.AspNetCore;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect;
using TEC.Security.Testing;

builder.Services.AddTecSecurity(builder.Configuration, security =>
{
    security.AddAspNetCore();
    if (Program.TestIssuer is { } emissor)
        security.AddTestJwt(emissor);   // não sobe fora de Development/Testing/Test
    else
        security.AddOpenIdConnectApi("Funcionarios", builder.Configuration.GetSection("Security:OpenIdConnect:Api"));
});

public partial class Program
{
    internal static TestTokenIssuer? TestIssuer { get; set; }
}
```

```csharp
// Teste (TUnit + Microsoft.AspNetCore.Mvc.Testing)
using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using TEC.Security.Testing;

public sealed class OrdersApiTests
{
    [Test]
    public async Task Manager_cancels_order()
    {
        using var emissor = new TestTokenIssuer();
        Program.TestIssuer = emissor;
        await using var factory = new WebApplicationFactory<Program>().WithWebHostBuilder(web => web.UseEnvironment("Testing"));

        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", emissor.CreateToken(t =>
        {
            t.ExternalTenantId = "tenant-de-teste";   // Security:Tenants:*:IdentityProviders:Test
            t.Roles.Add("Gerente");
            t.Scopes.Add("access_as_user");
        }));

        var resposta = await client.DeleteAsync("/pedidos/123");
        await Assert.That(resposta.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
    }
}
```

| Claim do token de teste | Vira |
|---|---|
| `sub` (`Subject`, padrão GUID novo) | `Id` |
| `tid` (`ExternalTenantId`) | Tenant pelo cadastro (`IdentityProviders:Test`) |
| `roles` / `scp` | Papéis / escopos (escopos ignorados em token de aplicação) |
| `idtyp=app` (`IsApplication`) | `Kind = Application` (senão `User`) |
| `name` | `Name` |

Casos de erro: `Lifetime`, `IssuedAt` (token expirado ou ainda não válido), `Audience`/`Issuer` diferentes e
`ExtraClaims` (ex.: tentar injetar `tec_perm`, que é descartado).

### Rodar localmente

```bash
# Unitários, como no CI
dotnet test --project TEC.Security.Tests --treenode-filter "/*/*/*/*[Category!=Integracao]"

# Sem ICU (como em containers mínimos)
DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 dotnet test --project TEC.Security.Tests -f net10.0 --treenode-filter "/*/*/*/*[Category!=Integracao]"

# Uma classe (assembly/namespace/classe/teste)
dotnet test --project TEC.Security.Tests -f net10.0 --treenode-filter "/*/*/FuzzingTests/*"

# Carga rápida
dotnet test --project TEC.Security.LoadTests -c Release -f net10.0 --treenode-filter "/*/*/*/*[Category=Carga-CI]"
```

```powershell
# PowerShell
$env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"; dotnet test --project TEC.Security.Tests -f net10.0 --treenode-filter "/*/*/*/*[Category!=Integracao]"
```

> [!WARNING]
> Não use `-nologo` com `dotnet test` no Microsoft.Testing.Platform: a opção é repassada ao executável de testes, que roda
> **0 testes** e sai com código 5.

> [!NOTE]
> O `TEC.Core` e o `TEC.Vault` vêm do feed `tec-interno` por padrão; entram como projeto só com
> `-p:TecUseLocalProjects=true` e os repositórios vizinhos presentes ([💻 Desenvolvimento local](desenvolvimento.md)).

### Suítes

<details>
<summary>Suítes de <code>TEC.Security.Tests</code></summary>

| Suíte | Rede | O que cobre |
|---|:---:|---|
| `IdentityFactoryTests` | ❌ | Normalização, descarte de `tec_*`, tenant, `RequireTenant`, limites, store de permissões, `RolesAsPermissions`, revalidação |
| `TenantRegistryTests` | ❌ | Cadastro, id externo sem diferenciar maiúsculas, duplicidade, recarga válida e inválida, appsettings |
| `ApiKeyTests` | ❌ | Geração, hash, expiração, formato, log sem segredo, validação do cadastro |
| `HttpSecurityTests` | ❌ | Ponta a ponta: fechado por padrão, 401/403, `alg:none`, HS256, chave/audiência/validade, emissor desconhecido, headers duplicados, tamanho, SignalR, API key, subida, `RunAs` |
| `OpenIdConnectApiTests` | ❌ | Token OpenID Connect aceito e normalizado, `realm_access` do Keycloak, audiência errada, portas de `AllowedHosts` (SEC-14); ponta a ponta do `Kind` (token sem sinal recusado, `Unresolved`, app do Entra ID sem `idtyp`) e de `MultiTenant = true` (tenant ativo, inativo, desconhecido, papel que não vira permissão, log sem o valor do tenant) |
| `OpenIdConnectIdentityTests` | ❌ | Regras de `Kind` (sinais padrão, `sub` igual ao client, prefixo, conflito, `Unresolved`, regra do `scp` do Entra ID, `preferred_username` que não decide, regras e seção `Kind` inválidas), `resource_access` só do client alvo (também no login web) e motivo de tenant sem o valor do token |
| `OpenIdConnectM2MTests` | ❌ | Obtenção e cache do token de client credentials; `expires_in` inválido, ausente, em texto e enorme; resposta acima do teto; corpo que trava cortado pelo tempo limite; status 3xx/4xx sem ler o corpo; opções inválidas impedem a subida; `HttpClient` sem redirecionamento nem cookies; log 3121 do `AccessTokenHandler` |
| `OpenIdConnectWebLoginTests` | ❌ | Segredo do login web lido do cofre a cada troca do código e no PAR (rotação sem reiniciar), segredo inexistente na subida e cofre fora do ar no login |
| `EventGuardTests` | ❌ | Delegates que não aprovam sozinhos: `OnMessageReceived`, `OnAuthenticationFailed` e troca de token/principal no `OnTokenValidated` (JWT); `OnMessageReceived`, `OnAuthorizationCodeReceived`, `OnTokenResponseReceived`, `OnAuthenticationFailed`, `OnTokenValidated` e `OnTicketReceived` (OIDC); cookie que reconstrói só a própria identidade e recusa gravar outra |
| `NormalizedIdentityTests` | ❌ | Principal forjado com todos os claims `tec_*` anônimo (inclusive vindo de outro middleware, 403), claims `tec_*` travados, `Clone`, indicador multi-tenant mantido na revalidação e aviso 3403 uma vez |
| `SecurityIssueRegressionTests` | ❌ | Uma regressão por issue corrigida (`Issue2` a `Issue13`): registro M2M no container, `PrivateKeyJwt`, tenant pelo emissor, segredo do login web, HTTPS em loopback, `resource_access` isolado, classificação User × Application, ganchos recusados pelo `JwtHardening`, `RolesAsPermissions` em multi-tenant, claims de tenant e papel exclusivos, endpoint M2M em HTTPS |
| `WebLoginTests` | ❌ | PKCE, 401 para API, `returnUrl`, cookie endurecido |
| `TokenAndCredentialTests` | ❌ | `AllowedHosts`, `Authorization` existente preservado, cache e renovação, concorrência, `returnUrl` |
| `ResilienceTests` | ❌ | Circuit breaker (cancelamento × tempo limite), token atual mantido com o provedor lento, token curto reaproveitado |
| `ReviewRegressionTests` | ❌ | Policy pelo `IAuthorizeData`, `PostConfigure`/eventos substituídos, logout de outra origem, permissões por tenant, `RunAs` paralelo, cookies OIDC, header de API key, metadados por HTTP |
| `TechnicalReviewRegressionTests` | ❌ | Revisão técnica: tempo limite do store de permissões, revogação de API key com outra chave inválida na edição, sessão web mantida em falha passageira do store, ganchos de enfraquecimento, `FallbackPolicy` e provedor de policies substituídos, log de recusas limitado (com varredura no máximo uma vez por intervalo) |
| `HardeningRegressionTests` | ❌ | Hash não canônico, Base64Url do Core, cadastro inválido relido 1×/s, nome de exibição (bidi, surrogates), cache de permissões (uma consulta, cancelamento, chave fixa, `null`), `RunAs` entre containers, registro duplicado, renovação com token atual, `Dispose`, limite de escopos, lista de algoritmos, OIDC, `TestTokenIssuer` |
| `Security/SecurityRegressionTests` | ❌ | Regressões achadas pelos testes de segurança (id externo fora do ASCII) |
| `Security/Fuzzing/`, `Security/Adversarial/` | ❌ | Veja [Testes de segurança](#testes-de-segurança) |

</details>

### Testes de segurança

Ficam em `TEC.Security.Tests/Security`, sobre a mesma API de referência (`SecuredTestApp`: JWT de teste, API key válida e
expirada, tenant ativo e inativo, `RequireTenant`).

| Classe | Técnica | O que garante |
|---|---|---|
| `Fuzzing/FuzzingTests` | Propriedades com FsCheck (separadores das codificações internas, prefixo `tec_` em várias caixas, controles, homógrafos, `ſ`/`ı`, surrogates soltos) | Formatos iguais a uma implementação de referência; nome de exibição seguro e idempotente; nenhuma API key forjada aceita e qualquer edição de uma válida recusada; normalização nunca lança e nunca aceita `tec_*` injetado; id externo só resolve se igual a um cadastrado; chave do cache injetiva; policy `TEC\|...` faz ida e volta; destino do token só HTTPS no host exato; tokens mutados nunca autorizam nem geram 5xx |
| `Adversarial/DosResistanceTests` | Credenciais gigantes, repetidas ou malformadas, medindo tempo e volume processado | 401 rápido para headers de 1 MB e repetidos; token com milhares de papéis recusado como inflado; JSON aninhado sem 5xx; inundação de `kid` desconhecido rápida; formatos em tempo linear; 1 milhão de papéis recusado sem processar tudo; cache além do limite sem erro |
| `Adversarial/LeakageTests` | Marcador secreto procurado em logs, respostas e exceções; respostas de recusa comparadas | **Sem oráculo** (toda recusa de token e de API key responde igual); token e segredo nunca no log; 403 sem a permissão exigida; `error_description` só em Development; falha do provedor sem detalhes; erros de cadastro sem ids externos nem hashes; injeção de linha impossível |
| `Adversarial/ConstantTimeTests` | Rápido: razão entre lotes em pares. Pesado (`Seguranca-Pesada`): teste t de Welch estilo dudect | API key de id inexistente custa o mesmo que id existente com segredo errado; a posição da diferença não muda o tempo; controle prova que o método detecta `string.Equals` |

```bash
# Testes estatísticos de tempo (≈ 1 min; feche outros programas)
dotnet test --project TEC.Security.Tests -c Release -f net10.0 --treenode-filter "/*/*/*/*[Category=Seguranca-Pesada]" --output detailed
```

> [!NOTE]
> Falha de propriedade do FsCheck mostra o contraexemplo e a semente; reproduza com `Config.QuickThrowOnFailure.WithReplay(...)`.
> `|t|` de Welch acima de 10 indica diferença de tempo detectável. As duas classes passam pelo **mesmo** delegate (um
> delegate por classe é compilado em separado pelo JIT e dava falso vazamento) e cada entrada existe em 64 cópias, em
> posições de memória sorteadas, usadas em rodízio. Exceção: no teste "id existente × inexistente" o critério é a
> diferença relativa das médias (< 5%), não o `|t|`: o id não é segredo e a busca no `Dictionary` (acerto × falha)
> difere por natureza em poucos nanossegundos; o que precisa ser igual é o SHA-256 e a comparação do segredo.

### Integração com provedor real

Não há testes de integração com um IdP real. A categoria `Integracao` está reservada (`TestCategories.Integration`) e o
filtro `Category!=Integracao` do CI continua valendo para quando eles existirem. Todos os testes atuais usam o
`TestTokenIssuer`, um servidor em memória ou um cofre falso; o projeto de testes não referencia cofre real nem lê
user-secrets.

### Carga

`TEC.Security.LoadTests` usa a `SecuredApiHost`: API protegida pelo TEC.Security em **Kestrel real** (`127.0.0.1`), com JWT
de teste, API key e um store de permissões que simula o banco. Cada cenário tem o status esperado; qualquer outro conta
como erro, **inclusive um ataque que passe**.

| Legítimos | Hostis (todos 401) |
|---|---|
| `jwt-autorizado` (usuários distintos) · `jwt-negado` (403) · `api-key` · `publico` | `sem-credencial` · `token-adulterado` · `token-expirado` · `token-outra-chave` · `token-alg-none` · `token-gigante` · `api-key-invalida` · `api-key-id-desconhecido` |

| Teste | Categoria | O que garante |
|---|---|---|
| `ConcurrencyTests` (7): `ApiKeyValidator_*`, `IdentityFactory_*`, `PermissionCache_ConcurrentMisses_FewSourceQueries`, `TenantRegistry_ReadsDuringReloads_*`, `ServiceTokenProvider_SingleAcquisitionPerScopeSet_*`, `AccessTokenHandler_*`, `SecurityContext_ParallelRunAs_*` | Carga-CI | Resultado concorrente igual ao sequencial; nenhuma identidade com tenant/permissão de outra; id externo ambíguo de uma versão com erro nunca resolvido para outro tenant; um token por conjunto de escopos; token nunca para destino proibido |
| `SmokeLoad_AllScenarios_ExpectedStatusOnly` | Carga-CI | Fumaça de carga HTTP em todos os cenários, zero erros |
| `SustainedLoad_ErrorRateLatencyAndPermissionCacheWithinLimits` | Carga-Pesada | Carga sustentada (`TEC_CARGA_API_SEGUNDOS`): zero erros, p99 e memória dentro dos limites, poucas consultas ao store |
| `HostileFlood_DoesNotStarveLegitimateTraffic` | Carga-Pesada | 80% de credenciais forjadas: nenhum ataque aceito, nenhuma requisição legítima recusada |
| `TenantRegistry_LargeCatalog_BuildLookupAndReload` | Carga-Pesada | Cadastro com `TEC_CARGA_TENANTS` tenants: montagem, consultas e recarga com leituras simultâneas |
| `PermissionCache_ManyDistinctIdentities_MemoryBounded` | Carga-Pesada | `TEC_CARGA_IDENTIDADES` identidades: memória para de crescer no limite de 50.000 |
| `InflatedIdentities_AtAndAboveItemLimit` | Carga-Pesada | 512 itens aceitos; acima, recusado rápido |
| `MixedWorkload_MemoryHandlesAndThroughputStayStable` | Carga-Pesada | Soak (`TEC_CARGA_SOAK_SEGUNDOS`): memória, handles e vazão estáveis |

```bash
# Pesados com os padrões (≈ 6 min), com relatório Markdown
TEC_CARGA_RELATORIOS=./relatorios \
  dotnet test --project TEC.Security.LoadTests -c Release -f net10.0 --treenode-filter "/*/*/*/*[Category=Carga-Pesada]"

# Soak de 10 minutos
TEC_CARGA_SOAK_SEGUNDOS=600 dotnet test --project TEC.Security.LoadTests -c Release -f net10.0 --treenode-filter "/*/*/SoakTests/*"
```

Os pesados rodam um de cada vez (`[NotInParallel]`), porque medem memória e vazão do processo. Cada um escreve o relatório
na saída do teste e, com `TEC_CARGA_RELATORIOS`, acrescenta em `carga.md` nessa pasta (o CI publica no resumo).

<details>
<summary>Resultados de referência (06/10/2026, Windows 11, 32 núcleos lógicos, .NET 10, Release)</summary>

Ordem de grandeza, não meta: os testes só falham em regressões grosseiras.

| Cenário | Resultado |
|---|---|
| API protegida, 64 conexões, 12 cenários | ~100 mil req/s, p50 0,3 ms, p99 4,3 ms, zero erros |
| Inundação com 80% de credenciais forjadas | ~90 mil req/s, todos os ataques recusados; p99 legítimo 4,8 → 5,6 ms |
| Soak em processo, carga mista | ~45–60 mil op/s; memória retida estável (~40 MB) |
| Cadastro com 100 mil tenants | Montagem 0,3 s; ~1,8 milhão de consultas/s; ~460 bytes por tenant |
| Cache de permissões com 200 mil identidades | ~420 mil normalizações/s; memória estável depois de 50 mil entradas |
| Tempo constante da API key | `\|t\|` ≈ 2 (id existente × inexistente); controle `string.Equals` ≈ 700–1.100 |

</details>

### Benchmarks

`TEC.Security.Benchmarks` (BenchmarkDotNet) não faz parte do `dotnet test`: rode sempre em **Release**.

| Classe | Mede |
|---|---|
| `ApiKeyBenchmarks` | Geração; validação aceita, com segredo errado, com id desconhecido (devem empatar) e malformada |
| `IdentityBenchmarks` | Normalização típica e inflada (512 itens), revalidação de sessão, leitura do `SecurityUser` |
| `TenantBenchmarks` | `FindByExternalId`, `Find` e montagem do cadastro, com 10 e 10 mil tenants |
| `ServiceTokenBenchmarks` | Token de serviço do cache, conferência de destino e envio pelo `AccessTokenHandler` |
| `RulesBenchmarks` | Validação de nomes, ids e nome de exibição, inclusive entrada hostil |
| `HttpPipelineBenchmarks` | Requisição completa em TestServer: anônima, JWT autorizado, 403, assinatura inválida, API key, sem credencial |

```bash
dotnet run -c Release --project TEC.Security.Benchmarks -f net10.0 -- --filter "*"
dotnet run -c Release --project TEC.Security.Benchmarks -f net10.0 -- --filter "*ApiKey*"
dotnet run -c Release --project TEC.Security.Benchmarks -f net10.0 -- --filter "*Http*" --job short
```

Resultados em `BenchmarkDotNet.Artifacts/results`. No CI, só pelo `performance.yml` manual (opção `benchmarks`).

### No CI

| Evento | Testes | Workflow |
|---|---|---|
| Pull request / merge queue | Unitários e `Carga-CI` (`net10.0` com cobertura e `net10.0` sem ICU) | `ci.yml` |
| `main` (push, agendado segunda 06:00 UTC / manual) | Os mesmos; no push, depois do `ci-ok`, a prévia é publicada | `ci.yml` |
| Manual (**Performance**) | `suite` = `pesadas` (padrão: `Carga-Pesada` + `Seguranca-Pesada`), `rapida` (`Carga-CI`) ou `todas`; benchmarks opcionais | `performance.yml` |
| Publicar versão | Unitários e `Carga-CI` (matriz + cobertura), antes da tag | `release.yml` |

Os `Carga-CI` (concorrência nos singletons e fumaça de carga, segundos, limites folgados) rodam no PR e na publicação junto
dos unitários. `Carga-Pesada` e `Seguranca-Pesada` não: tempo de parede em runner compartilhado é ruidoso e não pode
bloquear PR nem versão.

Variables e parâmetros: [⚙️ CI/CD](../.github/workflows/README.md).

### Escrevendo novos testes

- Correção de segurança ganha teste de regressão (em `Security/SecurityRegressionTests` ou `HardeningRegressionTests`);
  entrada não confiável nova ganha uma propriedade em `FuzzingTests` e, se houver limite de tamanho, um caso em
  `DosResistanceTests`.
- Toda recusa nova precisa responder igual às existentes: inclua o caso em `LeakageTests.Rejected*`.
- Singleton novo ou estado compartilhado: um teste em `ConcurrencyTests` comparando o resultado concorrente com o
  sequencial.
- Teste de tempo, memória ou vazão: rápido e com limites folgados → `Carga-CI`; longo ou sensível à máquina →
  `[Explicit]`, `Carga-Pesada` (ou `Seguranca-Pesada`) e `[NotInParallel(LoadSettings.HeavyExclusiveKey)]`.
- Cenário HTTP novo: acrescente em `SecurityScenarios` com o status esperado.
- Use as constantes de `TestCategories`, nunca a string da categoria.

---

## ⚙️ Opções

| Variável | Padrão | Uso |
|---|---|---|
| `TEC_CARGA_SOAK_SEGUNDOS` | `120` | Duração do soak |
| `TEC_CARGA_API_SEGUNDOS` | `60` | Duração da carga sustentada na API |
| `TEC_CARGA_API_CONCORRENCIA` | `64` | Conexões simultâneas na carga sustentada e na inundação |
| `TEC_CARGA_TENANTS` | `100000` | Tenants no teste de volume do cadastro |
| `TEC_CARGA_IDENTIDADES` | `200000` | Identidades no teste de volume do cache |
| `TEC_CARGA_RELATORIOS` | nenhum | Pasta onde os testes de carga acrescentam `carga.md` (o CI define e publica) |
| `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT` | — | `1` roda sem ICU |

Valores `TEC_CARGA_*` inválidos ou vazios usam o padrão.

> [!NOTE]
> As variáveis `TEC_TESTES_*` e `TEC_SECURITY_ENTRA_*` das versões anteriores deste documento não são lidas por nenhum
> teste atual.

---

## ❌ Erros

| Sintoma | Quando ocorre | O que fazer |
|---|---|---|
| `dotnet test` roda **0 testes** e sai com código 5 | `-nologo` (ou filtro que não casa nada) | Remova `-nologo`; confira o `--treenode-filter` |
| Os pesados não rodam | `[Explicit]`: só com a categoria | `--treenode-filter "/*/*/*/*[Category=Carga-Pesada]"` |
| Teste de tempo/memória falhou uma vez | CPU disputada (outros programas, testes em paralelo) | Repita em Release com a máquina ociosa |
| `HTTP 431` num cenário de carga | Header acima do limite do Kestrel (32 KB) | Cenários de token grande ficam entre `MaxTokenLength` e o limite do Kestrel |

---

## 🛡️ Segurança

> [!CAUTION]
> Quando existirem testes de integração, use app registrations e cofre **exclusivos de testes**, sem dados reais e sem
> permissões em recursos de produção.

- Nenhum teste atual acessa serviço externo: tokens, chaves e servidores são criados em memória.
- O `TestTokenIssuer` gera a chave na memória do processo e não grava nada; `AddTestJwt` impede a subida em produção.

---

## ❓ Perguntas frequentes

<details>
<summary>Como testo um usuário de outro tenant ou um token expirado?</summary>

`emissor.CreateToken(t => { t.ExternalTenantId = "outro"; t.IssuedAt = DateTimeOffset.UtcNow.AddHours(-1); })`. Para um
relógio controlado, passe um `TimeProvider` falso no construtor: `new TestTokenIssuer(time: fakeTime)`.

</details>

<details>
<summary>Posso usar o <code>TestTokenIssuer</code> com um emissor e audiência próprios?</summary>

Sim: `new TestTokenIssuer("https://emissor.meu-teste/", "api://minha-api")`. Valores vazios lançam `ArgumentException`.
Depois do `Dispose`, `CreateToken` lança `ObjectDisposedException`.

</details>

---
⬅️ [🛡️ Segurança](seguranca.md) · [📚 Índice](README.md) · [💻 Desenvolvimento local](desenvolvimento.md) ➡️
