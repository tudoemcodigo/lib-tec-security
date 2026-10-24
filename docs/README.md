<div align="center">
<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="Tudo em Código" width="90" />
</div>

[🏠 TEC.Security](../README.md) › 📚 Documentação

# 📚 Documentação do TEC.Security

> Referência completa dos quatro pacotes (`TEC.Security`, `TEC.Security.AspNetCore`, `TEC.Security.OpenIdConnect` e
> `TEC.Security.Testing`): como usar, opções, erros e cuidados de segurança, conferidos com o código.

## 📑 Sumário

- [🗂️ Temas](#️-temas)
- [🗺️ Mapa dos temas](#️-mapa-dos-temas)
- [📐 Convenções desta documentação](#-convenções-desta-documentação)

---

## 🗂️ Temas

| # | Tema | O que responde |
|:-:|---|---|
| 1 | [⚙️ Configuração](configuracao.md) | Como registrar (`AddTecSecurity`, `SecurityBuilder`, `AddAspNetCore`), todas as chaves da seção `Security`, recarga e o que impede a subida |
| 2 | [🔐 Autorização](autorizacao.md) | Como exigir permissões, papéis, escopos, tipos e esquemas com `[TecAuthorize]`/`RequireTecAuthorization`; fechado por padrão; 401 × 403 |
| 3 | [👤 Identidade e permissões](identidade-e-permissoes.md) | `ISecurityUser`, claims normalizados, `SecurityIdentityFactory`, `IPermissionStore`, cache de permissões, `SecurityRules` |
| 4 | [🏢 Tenants](tenants.md) | Cadastro de tenants, vínculo com os tenants dos provedores, recarga sem reinício, `ITenantRegistry` próprio |
| 5 | [🌐 Provedor OpenID Connect](provedor-openid-connect.md) | Keycloak, Auth0, Okta, Entra ID, Google, Cognito: API protegida, login web (OIDC + PKCE), client credentials, multi-tenant |
| 6 | [🪪 Provedor Entra ID](provedor-entra-id.md) | Microsoft Entra ID via OpenID Connect: app registration, claims, multi-tenant, login web, chamadas entre serviços e o que não existe |
| 7 | [🔁 Chamadas entre serviços](chamadas-entre-servicos.md) | Client credentials em `HttpClient`, `AllowedHosts` (com validação estrita de portas SEC-14), `CachingAccessTokenProvider`, circuit breaker |
| 8 | [🔑 API keys](api-keys.md) | Gerar, cadastrar, rotacionar e limitar tentativas de API keys guardadas só como hash |
| 9 | [🤖 Workers](workers.md) | Identidade de sistema, `RunAs`, mensageria e TEC.Cqrs fora do HTTP |
| 10 | [🧱 Novo provedor](novo-provedor.md) | Como plugar outro IdP: `JwtProviderDefinition`, `WebLoginDefinition`, `JwtHardening` e a lista de algoritmos |
| 11 | [🧬 Integrações TEC](integracoes-tec.md) | TEC.Core, TEC.Vault, TEC.Cqrs, TEC.ORM e TEC.Observability |
| 12 | [📈 Observabilidade](observabilidade.md) | Métricas, traces, eventos de log e alertas |
| 13 | [❌ Erros](erros.md) | `SecurityErrors`, respostas 401/403, exceções e diagnóstico |
| 14 | [🛡️ Segurança](seguranca.md) | Modelo de ameaças com o teste de cada controle, controles obrigatórios, limites, riscos residuais e checklist |
| 15 | [🧪 Testes](testes.md) | `TEC.Security.Testing` para a sua API; categorias, segurança, carga, benchmarks e variáveis `TEC_CARGA_*` |
| 16 | [💻 Desenvolvimento local](desenvolvimento.md) | Como compilar (feed `tec-interno` por padrão, repositórios vizinhos sob demanda) e regenerar lock files |
| 17 | [🔍 Revisão técnica](revisao-tecnica.md) | Revisão de segurança, código, organização e docs (2026-10-19): achados por severidade com `arquivo:linha`, correções e melhorias sugeridas |
| 18 | [🏛️ Decisões de arquitetura (ADRs)](adr/README.md) | Registros das decisões: identidade normalizada, fechado por padrão, permissões, tenants, API keys, tokens de serviço, workers e provedores |

Fora de `docs/`: [⚙️ CI/CD](../.github/workflows/README.md) · [📝 Changelog](../CHANGELOG.md) · READMEs dos pacotes
([TEC.Security](../TEC.Security/README.md), [AspNetCore](../TEC.Security.AspNetCore/README.md),
[OpenIdConnect](../TEC.Security.OpenIdConnect/README.md), [Testing](../TEC.Security.Testing/README.md)).

---

## 🗺️ Mapa dos temas

```mermaid
flowchart TD
    Q{"O que a aplicação precisa?"} -->|"proteger uma API"| API["🌐 provedor-openid-connect.md<br/>🪪 provedor-entra-id.md<br/>AddOpenIdConnectApi"]
    Q -->|"login de usuários num site"| WEB["🌐 provedor-openid-connect.md<br/>AddOpenIdConnectWebLogin"]
    Q -->|"integração sem OAuth"| KEY["🔑 api-keys.md"]
    Q -->|"chamar outro serviço"| SVC["🔁 chamadas-entre-servicos.md"]
    Q -->|"worker ou fila"| WRK["🤖 workers.md"]
    Q -->|"outro provedor"| NEW["🧱 novo-provedor.md"]
    API & WEB & KEY --> CFG["⚙️ configuracao.md"]
    CFG --> AUT["🔐 autorizacao.md"]
    AUT --> ID["👤 identidade-e-permissoes.md"]
    ID --> TEN["🏢 tenants.md"]
    SVC & WRK --> ID
    TEN -.-> OPS["📈 observabilidade.md<br/>❌ erros.md"]
    OPS -.-> SEG["🛡️ seguranca.md"]
    NEW -.-> TST["🧪 testes.md<br/>💻 desenvolvimento.md"]
    SEG -.-> TST
    SEG -.-> REV["🔍 revisao-tecnica.md<br/>🏛️ adr/README.md"]
```

---

## 📐 Convenções desta documentação

| Convenção | Significado |
|---|---|
| Fonte da verdade | O código atual: nomes, assinaturas, padrões, códigos de erro, eventos de log e métricas foram conferidos nele |
| Estrutura | Cada tema tem breadcrumb, 📑 Sumário, 🎯 Visão geral, 🚀 Uso, ⚙️ Opções, ❌ Erros, 🛡️ Segurança, ❓ Perguntas frequentes e rodapé de navegação |
| Decisões | Os [ADRs](adr/README.md) seguem o modelo Status, Data, Contexto, Decisão e Consequências, com links relativos para o código |
| Termos | *Identidade normalizada*: principal criado pelo `SecurityIdentityFactory` (claims `tec_*` com a marca `tec_normalized`). *Provedor*: tipo de IdP (`OpenIdConnect`, `ApiKey`, `Test`, `System`). *Esquema*: nome de registro no ASP.NET Core (ex.: `Funcionarios`) |
| `Result` | Métodos que retornam `Result`/`Result<T>` do [TEC.Core](https://github.com/tudoemcodigo/lib-tec-core) usam os códigos de [`SecurityErrors`](erros.md); recusas de credencial nunca lançam: viram 401/403 |
| Configuração inválida | Falha na **subida** (`InvalidOperationException` ou `OptionsValidationException`), citando o esquema e a regra |
| Placeholders | Valores entre `< >` (`<tenant-id>`, `<client-id-da-api>`, `<nome-do-cofre>`) são do seu ambiente; `contoso`, `Funcionarios` e `pedidos:ler` são exemplos |
| `CancellationToken` | Omitido das tabelas quando é o último parâmetro opcional |
| Alertas | `[!NOTE]` comportamento · `[!TIP]` boa prática · `[!IMPORTANT]` requisito · `[!WARNING]` armadilha · `[!CAUTION]` risco de segurança |

---
[🏠 README](../README.md) · [⚙️ Configuração](configuracao.md) ➡️
