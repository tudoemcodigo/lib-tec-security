<div align="center">
<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="Tudo em Código" width="90" />
</div>

[🏠 TEC.Security](../../README.md) › [📚 Documentação](../../docs/README.md) › ⚙️ CI/CD

# ⚙️ CI/CD e publicação

> Os três workflows do TEC.Security são curtos: chamam os workflows reutilizáveis do
> [tec-workflows](https://github.com/tudoemcodigo/tec-workflows) (tag `v1`) e só declaram o que é deste repositório
> (solução, testes e parâmetros de carga).

## 📑 Sumário

- [🎯 Visão geral](#-visão-geral)
- [📂 Arquivos](#-arquivos)
- [🔀 ci.yml](#-ciyml)
- [📦 release.yml](#-releaseyml)
- [⏱️ performance.yml](#️-performanceyml)
- [🔑 Variables e Secrets](#-variables-e-secrets)
- [🚀 Como publicar](#-como-publicar)
- [🛡️ Segurança](#️-segurança)
- [❓ Solução de problemas](#-solução-de-problemas)

---

## 🎯 Visão geral

```mermaid
flowchart LR
    subgraph PR["🔀 ci.yml → dotnet-ci.yml (PR / push na main)"]
        direction LR
        CV["convenções"] ~~~ BP["build + pack"] ~~~ U["unitários<br/>net10.0 · net10.0 sem ICU"]
        IT["Carga-CI<br/><sub>concorrência e fumaça HTTP</sub>"] ~~~ CQ["CodeQL"]
        OK["✅ ci-ok"]
        OK -- "só push na main" --> PV["📦 publicar-previa<br/><sub>X.Y.Z-preview.N · 4 pacotes</sub>"]
    end
    subgraph REL["⌨️ release.yml → dotnet-release.yml"]
        direction LR
        V["validar versão<br/><sub>X.Y.Z ou X.Y.Z-rc.N</sub>"] --> G["convenções · pack ·<br/>unit ×2 + cobertura · CodeQL"] --> TAG["🏷️ tag + Release"] --> PUB["📦 GitHub Packages<br/>4 pacotes"]
    end
    subgraph PERF["⌨️ performance.yml (só manual)"]
        RA["rapida<br/><sub>Carga-CI</sub>"] ~~~ HV["pesados<br/><sub>Carga-Pesada + Seguranca-Pesada</sub>"] ~~~ BM["benchmarks (opcional)<br/><sub>dotnet-benchmark.yml</sub>"]
    end
```

| Evento | Workflow | O que roda | Publica? |
|---|---|---|:---:|
| `pull_request` para a `main` / `merge_group` | `ci.yml` | Convenções, build + pack, unitários e `Carga-CI` em matriz, CodeQL → check `ci-ok` | ❌ |
| `push` na `main` (merge) | `ci.yml` | O mesmo e, com `ci-ok` verde, `publicar-previa` | ✅ `<Version>-preview.N` |
| `schedule` segunda 06:00 UTC / manual | `ci.yml` | O mesmo na `main`; CodeQL e auditoria com regras e vulnerabilidades novas | ❌ |
| Manual (**Performance**) | `performance.yml` | Input `suite`: `pesadas` (padrão, `Carga-Pesada` + `Seguranca-Pesada`), `rapida` (`Carga-CI`) ou `todas`; parâmetros e, se pedido, benchmarks | ❌ |
| Manual (**Publicar versão**) | `release.yml` | Convenções, pack, unitários ×2 (`net10.0` com cobertura e sem ICU) e CodeQL, depois tag, Release e push dos 4 pacotes | ✅ `X.Y.Z` ou `-rc.N` |

Só os testes pesados (`Carga-Pesada` e `Seguranca-Pesada`) ficam fora do PR e da publicação: tempo de parede em runner
compartilhado é ruidoso e não pode bloquear PR nem versão. Os `Carga-CI` (segundos, limites folgados) rodam junto dos
unitários no `ci.yml` e no `release.yml`.

> [!NOTE]
> O antigo `codeql.yml` e o script `resumo-testes.py` foram **removidos**: o CodeQL roda dentro do CI central
> (`dotnet-ci.yml`) e o resumo dos testes é feito pela action `test-summary` do tec-workflows.

---

## 📂 Arquivos

| Arquivo | Função |
|---|---|
| [`ci.yml`](ci.yml) | Validação de PR, do push na `main` (com publicação da prévia) e semanal na `main`, com `dotnet-ci.yml@v1` |
| [`release.yml`](release.yml) | Publicação de versão estável ou `-rc.N`, com `dotnet-release.yml@v1` |
| [`performance.yml`](performance.yml) | Testes de carga e benchmarks só sob demanda (manual), com `dotnet-test.yml@v1` e `dotnet-benchmark.yml@v1` |
| [`../dependabot.yml`](../dependabot.yml) · [`../zizmor.yml`](../zizmor.yml) | Canônicos do tec-workflows (não editar aqui) |

Não há scripts em `.github/scripts/` nem testes de integração com serviços externos.

---

## 🔀 ci.yml

| Entrada | Valor |
|---|---|
| `solution` | `TEC.Security.slnx` |
| `private-feed` | `true` (depende de `TEC.Core` e `TEC.Vault` do feed `tec-interno`) |
| `unit-tests` | `TEC.Security.Tests /*/*/*/*[Category!=Integracao]` e `TEC.Security.LoadTests /*/*/*/*[Category=Carga-CI]` |

O `ci.yml` não passa `integration-tests`, `azure-client-id`, `azure-tenant-id` nem `azure-env`: não há testes de
integração com serviços externos (a categoria `Integracao` existe, mas está sem testes).

- Gatilhos: `pull_request` e `merge_group` para a `main`, `push` na `main`, `schedule` (segunda 06:00 UTC) e manual.
- Permissões: `contents: read` no topo; o job recebe também `pull-requests`, `actions`, `security-events` (leitura),
  `packages: write` (só o `publicar-previa` publica, no push na `main`) e `id-token: write` (teto exigido pelo `dotnet-test.yml`
  reutilizável; nenhum job deste repositório faz login no Azure).
- No push na `main`, depois do `ci-ok` verde, o job `publicar-previa` publica os 4 pacotes como
  `<Version do Directory.Build.props>-preview.N` (N sequencial por versão, reinicia a cada nova `<Version>`; ex.: `0.0.1-preview.3`). Se a tag `v<Version>` já existe,
  o CI não falha: valida tudo normalmente, o `build + pack` emite um `::notice::` e o `publicar-previa` é pulado (suba a
  `<Version>` para voltar a gerar prévias). Em PR nada é publicado.
- `Carga-CI` roda aqui; `Carga-Pesada` e `Seguranca-Pesada` ficam só no `performance.yml`.
- `concurrency` por ref no PR, cancelando execuções antigas do mesmo PR; fora de PR, um grupo por execução (nenhum push na `main` perde a prévia).
- PR só de documentação (`docs/`, LICENSE, CHANGELOG, READMEs de `.github/`) pula os jobs pesados. Os READMEs das pastas dos
  pacotes vão no `.nupkg` e **não** contam como só documentação.

---

## 📦 release.yml

Disparo manual (**Actions → Publicar versão → Run workflow**) com a entrada `versao` (`X.Y.Z` ou `X.Y.Z-rc.N`; prévias
saem do `ci.yml` no push na `main`).

| Entrada | Valor |
|---|---|
| `version` | `${{ inputs.versao }}` |
| `solution` / `private-feed` / `unit-tests` | Os mesmos do `ci.yml` (unitários e `Carga-CI`) |

Sequência: valida a versão (disparado **da `main`**; a tag `vX.Y.Z` não pode existir) → convenções, pack, unitários ×2
(`net10.0` com relatório de cobertura e `net10.0` sem ICU) e CodeQL em paralelo → só com **todos** verdes cria a tag e o Release e publica os 4
pacotes no GitHub Packages. Sem `Carga-Pesada` nem `Seguranca-Pesada`.
`concurrency: publicar-versao` sem cancelamento.

Permissões do job: `contents: write` (tag/Release), `packages: write` (push), `actions`/`security-events: read`
(CodeQL), `checks: read` e `pull-requests: read` (portões), `attestations: write` (proveniência) e `id-token: write`
(exigido pela assinatura do workflow de testes reutilizável).

---

## ⏱️ performance.yml

Só manual (`workflow_dispatch`): os testes de carga não rodam no PR nem na publicação, porque tempo de parede em runner
compartilhado é ruidoso e não pode bloquear PR nem versão.

| Entrada | Padrão | Variável | Uso |
|---|---|---|---|
| `suite` | `pesadas` | — | `pesadas` (job `pesados`), `rapida` (job `rapida`) ou `todas` |
| `soak_segundos` | `600` | `TEC_CARGA_SOAK_SEGUNDOS` | Duração do soak em processo |
| `api_segundos` | `120` | `TEC_CARGA_API_SEGUNDOS` | Carga sustentada na API protegida |
| `tenants` | `100000` | `TEC_CARGA_TENANTS` | Tenants no teste de volume do cadastro |
| `identidades` | `200000` | `TEC_CARGA_IDENTIDADES` | Identidades no teste de volume do cache de permissões |
| `benchmarks` | `false` | — | Roda também o `TEC.Security.Benchmarks` (`dotnet-benchmark.yml`, `net10.0`) |
| `benchmark_filtro` | `*` | — | Filtro do BenchmarkDotNet |

- Job `rapida`: `TEC.Security.LoadTests [Category=Carga-CI]` (segundos), artefato `carga`.
- Job `pesados`: `TEC.Security.LoadTests [Category=Carga-Pesada]` e `TEC.Security.Tests [Category=Seguranca-Pesada]`,
  `timeout-minutes: 120`, artefato `pesados`. Sem login no Azure.
- Os relatórios de carga são gravados em `$TEC_CARGA_RELATORIOS/carga.md` (pasta definida pelo workflow central) e
  publicados no resumo da execução.
- `concurrency: performance-<ref>` sem cancelamento.

> [!TIP]
> Medição de tempo em runner compartilhado tem ruído: compare **tendências** entre execuções, não números absolutos.

---

## 🔑 Variables e Secrets

**Organização** `tudoemcodigo` (*Settings → Secrets and variables*), com acesso aos repositórios `lib-tec-*`:

| Nome | Tipo | Uso |
|---|---|---|
| `PACKAGES_READ_TOKEN` | Secret **do Dependabot** | PAT classic `read:packages` para o Dependabot restaurar `TEC.Core` e `TEC.Vault` |

Os workflows deste repositório não leem nenhuma Variable nem Secret de Actions: o restore e a publicação usam o
`GITHUB_TOKEN` efêmero e não há login no Azure. As Variables `AZURE_CLIENT_ID`, `TEC_TESTES_*` e `TEC_SECURITY_ENTRA_*`
descritas em versões anteriores deste documento ficaram sem uso (só voltam quando existirem testes de integração).

---

## 🚀 Como publicar

1. As dependências TEC.* (`TEC.Core`, `TEC.Vault`) já estão no feed na versão referenciada.
2. Regenere e commite o lock em modo pacote:
   `dotnet restore TEC.Security.slnx --force-evaluate`.
3. Atualize o [CHANGELOG](../../CHANGELOG.md) e confira a `Version` do `Directory.Build.props`.
4. PR → `ci / ci-ok` verde → merge. O CI do push na `main` publica a prévia `<Version>-preview.N`.
5. Versão estável ou rc: **Actions → Publicar versão → Run workflow** (da `main`) com a versão (ex.: `0.0.1` ou
   `0.0.1-rc.1`).
6. Primeira publicação: em *Package settings* de cada pacote, visibilidade **pública** e acesso dos repositórios da
   organização.
7. Para gerar novas prévias depois de publicar `X.Y.Z`, suba a `Version` do `Directory.Build.props` para a próxima
   (com a tag `v<Version>` existente, o CI da `main` valida tudo, mas não publica prévia até esse ajuste).

| Pacote publicado | Pasta |
|---|---|
| `TEC.Security` | `TEC.Security/` |
| `TEC.Security.AspNetCore` | `TEC.Security.AspNetCore/` |
| `TEC.Security.OpenIdConnect` | `TEC.Security.OpenIdConnect/` |
| `TEC.Security.Testing` | `TEC.Security.Testing/` |

> [!IMPORTANT]
> Os quatro pacotes saem sempre com a **mesma versão**. O GitHub Packages não permite sobrescrever: uma versão publicada
> não pode ser repetida.

---

## 🛡️ Segurança

| Controle | Como |
|---|---|
| Menor privilégio | `contents: read` no topo; escrita só no `release.yml` e no `publicar-previa` do `ci.yml` (`packages: write`, push na `main`); `id-token: write` apenas como teto exigido pelos workflows reutilizáveis de teste (sem login no Azure) |
| Actions fixadas | Terceiros por SHA, tec-workflows por `v1`; `zizmor` audita; Dependabot com cooldown de 7 dias |
| Sem credencial no disco | `persist-credentials: false` em todo checkout (workflows centrais) |
| Sem pacote órfão | Tag + Release antes do push; release só com todos os portões verdes |
| Cadeia de suprimentos | `restore --locked-mode`, `NuGetAudit` como erro, `packageSourceMapping`, CodeQL `security-extended` |

---

## ❓ Solução de problemas

<details>
<summary><code>NU1100</code>, <code>401</code> ou <code>403</code> ao restaurar <code>TEC.Core</code>/<code>TEC.Vault</code></summary>

Pacote ainda não publicado, privado ou sem acesso deste repositório. Publique as dependências antes e libere o acesso em
*Package settings*.

</details>

<details>
<summary><code>A tag vX.Y.Z já existe</code> / <code>Execute a partir da main</code></summary>

Escolha outra versão ou dispare o **Publicar versão** selecionando a branch `main`.

</details>

<details>
<summary>Push na <code>main</code> não gerou prévia</summary>

A `Version` do `Directory.Build.props` já foi lançada (a tag `v<Version>` existe). O CI não falha: valida tudo
(convenções, build + pack, unitários e `Carga-CI`, CodeQL, `ci-ok`), o `build + pack` emite o aviso *"A versão X já foi
publicada (tag vX): nenhuma prévia gerada..."* e o `publicar-previa` é pulado. É o esperado quando o componente fica
numa versão publicada e recebe só correções. Para voltar a gerar prévias, abra um PR subindo a `Version` para a próxima.

</details>

---
[🏠 TEC.Security](../../README.md) · [📚 Documentação](../../docs/README.md) · [🧪 Testes](../../docs/testes.md)
