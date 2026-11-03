<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Security" width="120" />

# 🛡️ TEC.Security

**Autenticação e autorização com uma única API para qualquer provedor de login: fechado por padrão, multi-tenant e sem segredos na aplicação.**

OpenID Connect agnóstico (Keycloak, Auth0, Okta, Microsoft Entra ID, Google, Cognito) · `[TecAuthorize]` por permissão · Tenants por configuração · API keys · Login web (OIDC + PKCE) · Chamadas entre serviços M2M (Client Credentials) · Workers · .NET 10 · Native AOT

[![CI](https://github.com/tudoemcodigo/lib-tec-security/actions/workflows/ci.yml/badge.svg)](https://github.com/tudoemcodigo/lib-tec-security/actions/workflows/ci.yml)
[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](#-compatibilidade)
[![Native AOT](https://img.shields.io/badge/Native%20AOT-compat%C3%ADvel-512BD4)](#-compatibilidade)
[![Versão](https://img.shields.io/badge/vers%C3%A3o-0.0.1-blue)](CHANGELOG.md)
[![Licença: Apache 2.0](https://img.shields.io/badge/licen%C3%A7a-Apache%202.0-blue)](LICENSE)

[📥 Instalação](#-instalação) · [🚀 Início rápido](#-início-rápido) · [📚 Documentação](docs/README.md) · [📝 Changelog](CHANGELOG.md) · [⚙️ CI/CD](.github/workflows/README.md)

</div>

---

## 📑 Sumário

- [✨ Por que usar](#-por-que-usar)
- [📦 Pacotes](#-pacotes)
- [🧬 Ecossistema TEC](#-ecossistema-tec)
- [📥 Instalação](#-instalação)
- [🚀 Início rápido](#-início-rápido)
- [🧭 O que tem dentro](#-o-que-tem-dentro)
- [🧩 Diagrama de arquitetura](#-diagrama-de-arquitetura)
- [📚 Documentação](#-documentação)
- [⚡ Compatibilidade](#-compatibilidade)
- [🛡️ Segurança](#️-segurança)
- [🧪 Testes](#-testes)
- [🤝 Contribuição](#-contribuição)
- [🏷️ Versionamento](#️-versionamento)
- [📄 Licença](#-licença)

---

## ✨ Por que usar

| Sem o TEC.Security | Com o TEC.Security |
|---|---|
| Cada sistema configura `AddJwtBearer` de um jeito; alguém desliga `ValidateAudience` "para funcionar" | Validação endurecida em todo provedor; os controles obrigatórios **não podem** ser desligados (a aplicação não sobe), nem por `PostConfigure` |
| Endpoint esquecido sem `[Authorize]` fica público | Fechado por padrão: sem atributo, exige identidade; `[TecAuthorize]` + `[AllowAnonymous]` impede a subida |
| Código lê `roles`, `scp`, `realm_access`... de cada provedor | `ISecurityUser` com id, tenant, papéis, escopos e permissões normalizados, iguais para qualquer provedor |
| Multi-tenant aceitando "qualquer tenant" do provedor | Com `MultiTenant`, só tenants **ativos** no cadastro (appsettings com recarga, ou banco); desativar vale na próxima requisição |
| Claim `permissions` injetado por um IdP mal configurado vira permissão | Claims `tec_*` vindos do provedor são descartados; tenant e permissões vêm do cadastro da aplicação |
| Client secret no `appsettings` para chamar outra API | Só o **nome** do segredo na configuração; o valor vem do TEC.Vault |
| Token de serviço enviado para qualquer URL (SSRF) | Token anexado só aos `AllowedHosts`, com HTTPS |
| 401/403 em formatos diferentes, com o motivo da recusa | `ApiResponse` padrão do TEC.Core; motivo só no log de auditoria e nas métricas |

- ✅ **Um atributo para tudo:** `[TecAuthorize]` em controllers, Minimal APIs, gRPC, hubs SignalR e Blazor.
- ✅ **Vários provedores ao mesmo tempo:** o esquema é escolhido por requisição (emissor, header, cookie).
- ✅ **Seguro sob carga:** limites contra tokens inflados, cache de permissões com uma consulta por identidade, tempo
  constante nas API keys, nada de token ou segredo em log.
- ✅ **Fora do HTTP também:** identidade de sistema e `RunAs` para workers e filas.

## 📦 Pacotes

| Pacote | Para que serve | Quando instalar | Depende de |
|---|---|---|---|
| [`TEC.Security`](TEC.Security/README.md) | Núcleo sem ASP.NET Core: `ISecurityUser`, `ICurrentUser`, `ICurrentTenant`, `ISecurityContext`, tenants, `IPermissionStore`, API keys, `AccessTokenHandler`, erros e telemetria | Vem com os outros; sozinho em workers sem HTTP | `TEC.Core`, `Microsoft.Extensions.*`, `Polly.Core` |
| [`TEC.Security.AspNetCore`](TEC.Security.AspNetCore/README.md) | Escolha do provedor por requisição, JWT endurecido, `[TecAuthorize]`, políticas fechadas, 401/403 padronizados, API key, login web, base para provedores | APIs e sites ASP.NET Core (vem com o provedor) | `TEC.Security`, `Microsoft.AspNetCore.Authentication.JwtBearer` e `.OpenIdConnect` |
| [`TEC.Security.OpenIdConnect`](TEC.Security.OpenIdConnect/README.md) | OpenID Connect agnóstico: Keycloak, Auth0, Okta, Entra ID, Google, Cognito, M2M Client Credentials, login web com PKCE | Aplicações que usam qualquer IdP OIDC | `TEC.Security.AspNetCore`, `TEC.Vault`, `Polly.Core` |
| [`TEC.Security.Testing`](TEC.Security.Testing/README.md) | Emissor de tokens para testar **a sua** API, bloqueado fora de Development, Testing e Test | Projetos de teste | `TEC.Security.AspNetCore` |

Os quatro pacotes saem sempre com a mesma versão e trazem `lib/net10.0`, a documentação XML em português e um README
próprio.

## 🧬 Ecossistema TEC

```mermaid
flowchart BT
    Core["🧰 TEC.Core<br/><sub>Result, erros, utilitários</sub>"]
    Vault["🔐 TEC.Vault<br/><sub>segredos, chaves, certificados</sub>"]
    Cqrs["🧭 TEC.Cqrs<br/><sub>commands, queries, pipeline</sub>"]
    Sec["🛡️ TEC.Security<br/><sub>autenticação, autorização</sub>"]
    Obs["📡 TEC.Observability<br/><sub>traces, métricas, logs</sub>"]
    Orm["🗄️ TEC.ORM<br/><sub>persistência</sub>"]
    Vault --> Core
    Cqrs --> Core
    Sec --> Core
    Sec --> Vault
    Orm --> Core
    Orm --> Cqrs
    Orm --> Vault
    classDef atual fill:#512BD4,color:#fff,stroke:#512BD4,stroke-width:2px
    class Sec atual
```

O TEC.Security decide **quem** executa cada operação. A identidade que ele normaliza chega aos outros componentes pelo
`ICurrentUser` do TEC.Core, sem que eles dependam dele.

| Componente | Relação com o TEC.Security |
|---|---|
| 🧰 [TEC.Core](https://github.com/tudoemcodigo/lib-tec-core) | Dependência: `ICurrentUser` (implementado aqui), `Result`/`Error`, `AppException`, `ApiResponse`, `SingleFlight`, `Base64UrlEncoder`, `SensitiveDataMasker` |
| 🔐 [TEC.Vault](https://github.com/tudoemcodigo/lib-tec-vault) | Dependência do `TEC.Security.OpenIdConnect`: segredo do cliente (`ISecretReader`) do login web e das chamadas entre serviços |
| 🧭 [TEC.Cqrs](https://github.com/tudoemcodigo/lib-tec-cqrs) | Independente: `[AuthorizeRequest]` avalia a identidade normalizada |
| 🗄️ [TEC.ORM](https://github.com/tudoemcodigo/lib-tec-orm) | Independente: a auditoria lê o `ICurrentUser` registrado aqui |
| 📡 [TEC.Observability](https://github.com/tudoemcodigo/lib-tec-observability) | Independente: assina o Meter e o ActivitySource `TEC.Security` |

## 📥 Instalação

Os pacotes estão no **GitHub Packages** da organização `tudoemcodigo`, que sempre exige autenticação (mesmo para leitura).
Crie um PAT *classic* com o escopo `read:packages`, registre a origem com o nome `tec-interno` e instale o provedor (ele
traz `TEC.Security.AspNetCore` e `TEC.Security`):

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>

dotnet add package TEC.Security.OpenIdConnect --version 0.0.1
dotnet add package TEC.Security.Testing --version 0.0.1    # só no projeto de testes
```

> [!IMPORTANT]
> Versão inaugural: **0.0.1**. Para evitar *dependency confusion*, mapeie `TEC.*` só para a origem
> `tec-interno` no `nuget.config` da aplicação (`packageSourceMapping`).

## 🚀 Início rápido

**1. Configure a API, os tenants e as permissões** no `appsettings.json` (nenhum valor é segredo):

```json
{
  "Security": {
    "RequireTenant": true,
    "OpenIdConnect": {
      "Api": { "Authority": "https://auth.empresa.com/realms/corp", "Audience": "api-pedidos", "MultiTenant": true }
    },
    "Tenants": {
      "contoso": { "Name": "Contoso", "IdentityProviders": { "OpenIdConnect": [ "https://auth.empresa.com/realms/corp" ] } }
    },
    "Permissions": {
      "Roles": { "Gerente": [ "pedidos:ler", "pedidos:cancelar" ] }
    }
  }
}
```

**2. Registre a segurança** no `Program.cs`:

```csharp
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddAspNetCore()
    .AddOpenIdConnectApi("Keycloak", builder.Configuration.GetSection("Security:OpenIdConnect:Api")));

var app = builder.Build();

app.MapGet("/pedidos", (ISecurityUser usuario) => $"Pedidos do tenant {usuario.TenantId}")
   .RequireTecAuthorization(permissions: "pedidos:ler");
app.MapGet("/saude", () => "ok").AllowAnonymous();

app.Run();
```

**3. Proteja controllers** com o mesmo atributo:

```csharp
using Microsoft.AspNetCore.Mvc;
using TEC.Security.AspNetCore.Authorization;

[ApiController, Route("pedidos")]
[TecAuthorize(Permissions = "pedidos:ler")]
public sealed class PedidosController : ControllerBase
{
    [HttpDelete("{id:guid}"), TecAuthorize(Permissions = "pedidos:cancelar", Kinds = TecPrincipalKinds.User)]
    public IActionResult Cancelar(Guid id) => NoContent();
}
```

Endpoints sem atributo já exigem identidade, 401/403 saem no formato do TEC.Core e configuração errada ou insegura derruba
a **subida**, não a primeira requisição. Entra ID, login web, API keys e workers: [📚 documentação](docs/README.md).

## 🧭 O que tem dentro

```mermaid
flowchart LR
    REQ["Requisição"] --> SEL{"Seletor TEC<br/>lê a credencial sem confiar"}
    SEL -->|"iss de um provedor"| ENTRA["JwtBearer OpenID Connect<br/>validação endurecida"]
    SEL -->|"X-Api-Key"| KEY["API key<br/>hash SHA-256"]
    SEL -->|"cookie"| WEB["Login web<br/>OIDC + PKCE"]
    SEL -->|"desconhecida"| NONE["TEC.None → 401"]
    ENTRA & KEY & WEB --> NORM["SecurityIdentityFactory<br/>descarta tec_* · tenant do cadastro<br/>papéis → permissões"]
    NORM --> AUTHZ["[TecAuthorize]<br/>permissões · papéis · escopos · tipo"]
    AUTHZ --> APP["ISecurityUser · ICurrentUser · ICurrentTenant"]
    TEN[("Security:Tenants<br/>recarga sem reinício")] -.-> NORM
    PERM[("IPermissionStore<br/>appsettings ou banco + cache")] -.-> NORM
```

| Recurso | Peças principais |
|---|---|
| 👤 Identidade normalizada | `ISecurityUser`, `TecClaimTypes`, `SecurityIdentityFactory`, `ExternalIdentity` |
| 🔐 Autorização | `[TecAuthorize]`, `RequireTecAuthorization`, `TecPrincipalKinds`, `FallbackPolicy` fechada |
| 🏢 Tenants e permissões | `ITenantRegistry`, `ICurrentTenant`, `IPermissionStore`, `UsePermissionStore<T>()` com cache |
| 🌐 OpenID Connect (inclui Entra ID) | `AddOpenIdConnectApi`, `AddOpenIdConnectWebLogin`, `MapTecWebLogin` |
| 🔁 Serviços | `AddOpenIdConnectClient`, `AddOpenIdConnectAccessToken`, `AccessTokenHandler`, `CachingAccessTokenProvider` |
| 🔑 API keys | `ApiKeyGenerator`, `AddApiKeys`, `Security:ApiKeys` |
| 🤖 Workers | `ISecurityContext.CreateSystemPrincipalAsync`, `RunAs` |
| 🧱 Extensão | `AddJwtBearerProvider`, `AddWebLoginProvider`, `JwtHardening` |
| 🧪 Testes | `TestTokenIssuer`, `AddTestJwt` |

## 🧩 Diagrama de arquitetura

Componentes e ligações do `TEC.Security`, gerados pelo [GitDiagram](https://gitdiagram.com/tudoemcodigo/lib-tec-security) a partir da `main` em 02/11/2026. O diagrama é gerado por IA a partir de uma amostra do código: use-o como mapa de leitura, não como contrato.

```mermaid
flowchart TD

subgraph group_core["Core identity"]
  node_keyvalidator["API key validation<br/>[ApiKeyValidator.cs]"]
  node_external["External identity"]
  node_identityfactory["Identity normalization"]
  node_tenantregistry[("Tenant registry")]
  node_permissionstore[("Permission store")]
  node_securityuser["Normalized user<br/>[SecurityUser.cs]"]
end

subgraph group_http["HTTP security"]
  node_selector["Scheme selection"]
  node_jwt["JWT authentication"]
  node_apikeyauth["API key authentication"]
  node_authorization["Permission authorization"]
  node_authresult["401/403 response"]
  node_websetup["Web login setup"]
  node_loginendpoints["Login endpoints"]
end

subgraph group_oidc["OIDC provider"]
  node_oidcsetup["OIDC registration"]
  node_oidcidentity["OIDC identity mapping"]
  node_tokenprovider["Client credentials"]
end

subgraph group_outbound["Service tokens"]
  node_tokenhandler["Outbound token handler"]
end

subgraph group_ops["Context and telemetry"]
  node_context["Security context<br/>[SecurityContext.cs]"]
  node_diagnostics["Security diagnostics"]
end

node_caller(("API client"))
node_aspnet(("ASP.NET request"))
node_idp(("Identity provider"))
node_vault[("TEC.Vault")]
node_endpoint["Secured endpoint"]
node_worker(("Worker or service"))

node_caller -->|"sends request"| node_aspnet
node_aspnet -.->|"selects scheme"| node_selector
node_selector -.->|"dispatches JWT"| node_jwt
node_selector -.->|"dispatches API key"| node_apikeyauth
node_apikeyauth -->|"validates key"| node_keyvalidator
node_keyvalidator -->|"creates identity"| node_external
node_jwt -.->|"maps claims"| node_oidcidentity
node_oidcidentity -->|"creates identity"| node_external
node_external -->|"normalizes"| node_identityfactory
node_identityfactory -->|"resolves tenant"| node_tenantregistry
node_identityfactory -->|"loads permissions"| node_permissionstore
node_identityfactory -->|"produces claims"| node_securityuser
node_securityuser -.->|"checks permissions"| node_authorization
node_authorization -.->|"allows access"| node_endpoint
node_authorization -->|"handles denial"| node_authresult
node_authresult -->|"writes response"| node_aspnet
node_websetup -.->|"configures login"| node_loginendpoints
node_loginendpoints -.->|"starts OIDC login"| node_idp
node_oidcsetup -->|"registers mapping"| node_oidcidentity
node_oidcsetup -.->|"registers web login"| node_websetup
node_worker -.->|"sends service request"| node_tokenhandler
node_tokenhandler -->|"requests token"| node_tokenprovider
node_tokenprovider -.->|"reads secret"| node_vault
node_tokenprovider -.->|"requests token"| node_idp
node_worker -.->|"runs as identity"| node_context
node_identityfactory -->|"backs context"| node_context
node_identityfactory -.->|"records events"| node_diagnostics
node_authorization -.->|"records denials"| node_diagnostics


classDef toneNeutral fill:#f8fafc,stroke:#334155,stroke-width:1.5px,color:#0f172a
classDef toneBlue fill:#dbeafe,stroke:#2563eb,stroke-width:1.5px,color:#172554
classDef toneAmber fill:#fef3c7,stroke:#d97706,stroke-width:1.5px,color:#78350f
classDef toneMint fill:#dcfce7,stroke:#16a34a,stroke-width:1.5px,color:#14532d
classDef toneRose fill:#ffe4e6,stroke:#e11d48,stroke-width:1.5px,color:#881337
classDef toneIndigo fill:#e0e7ff,stroke:#4f46e5,stroke-width:1.5px,color:#312e81
classDef toneTeal fill:#ccfbf1,stroke:#0f766e,stroke-width:1.5px,color:#134e4a
class node_keyvalidator,node_external,node_identityfactory,node_tenantregistry,node_permissionstore,node_securityuser,node_caller toneBlue
class node_selector,node_jwt,node_apikeyauth,node_authorization,node_authresult,node_websetup,node_loginendpoints,node_vault toneAmber
class node_oidcsetup,node_oidcidentity,node_tokenprovider,node_aspnet toneMint
class node_tokenhandler,node_worker toneRose
class node_context,node_diagnostics,node_idp,node_endpoint toneIndigo
```

## 📚 Documentação

| Arquivo | O que responde |
|---|---|
| [⚙️ Configuração](docs/configuracao.md) | Como registrar, todas as chaves de `Security`, recarga e validações na subida |
| [🔐 Autorização](docs/autorizacao.md) | Como usar `[TecAuthorize]`, o que é fechado por padrão, 401 × 403 |
| [👤 Identidade e permissões](docs/identidade-e-permissoes.md) | `ISecurityUser`, claims normalizados, fonte de permissões e cache |
| [🏢 Tenants](docs/tenants.md) | Cadastro de tenants, vínculo com os tenants dos provedores, cadastro em banco |
| [🌐 Provedor OpenID Connect](docs/provedor-openid-connect.md) | API, login web e client credentials para Keycloak, Auth0, Okta, Entra ID, Google e Cognito |
| [🪪 Provedor Entra ID](docs/provedor-entra-id.md) | Microsoft Entra ID via OpenID Connect: app registration, claims, multi-tenant, login web e o que não existe |
| [🔁 Chamadas entre serviços](docs/chamadas-entre-servicos.md) | Client credentials, `AllowedHosts`, cache, circuit breaker e falhas do provedor |
| [🔑 API keys](docs/api-keys.md) | Gerar, cadastrar, rotacionar e limitar tentativas |
| [🤖 Workers](docs/workers.md) | Identidade de sistema, `RunAs`, filas e TEC.Cqrs fora do HTTP |
| [🧱 Novo provedor](docs/novo-provedor.md) | Como plugar outro IdP com as mesmas garantias |
| [🧬 Integrações TEC](docs/integracoes-tec.md) | Core, Vault, Cqrs, ORM e Observability |
| [📈 Observabilidade](docs/observabilidade.md) | Métricas (`tec.security.*`), traces, eventos de log (3000-3999) e alertas |
| [❌ Erros](docs/erros.md) | Códigos de `SecurityErrors`, respostas e exceções |
| [🛡️ Segurança](docs/seguranca.md) | Modelo de ameaças, controles com os testes, limites, riscos residuais e checklist |
| [🧪 Testes](docs/testes.md) | Testar a sua API; categorias, carga, benchmarks, variáveis `TEC_CARGA_*` |
| [💻 Desenvolvimento local](docs/desenvolvimento.md) | Como compilar (feed `tec-interno` por padrão, repositórios vizinhos sob demanda) e regenerar lock files |
| [🔍 Revisão técnica](docs/revisao-tecnica.md) | Revisão histórica de segurança, código, organização e docs (2026-10-19, quando ainda existia o pacote `TEC.Security.EntraId`): achados com `arquivo:linha`, correções e melhorias sugeridas |
| [🏛️ Decisões de arquitetura (ADRs)](docs/adr/README.md) | Registros das decisões: identidade normalizada, fechado por padrão, permissões, tenants, API keys, tokens de serviço, workers, provedores e tipo da identidade (`Kind`) |
| [⚙️ CI/CD](.github/workflows/README.md) | Workflows, gatilhos, Variables e como publicar |

## ⚡ Compatibilidade

| Item | Suporte |
|---|---|
| .NET | `net10.0` (LTS); pacotes de autenticação do ASP.NET Core 10.0.x |
| Native AOT / trimming | ✅ `IsAotCompatible` em todos os pacotes: binding de configuração gerado em compilação, JSON do 401/403 com `JsonSerializerContext`, logs por *source generator* |
| Sem ICU (`InvariantGlobalization`) | ✅ testado no CI (todos os formatos aceitam só ASCII) |
| Hospedagem | Controllers, Razor Pages, Minimal APIs, gRPC, SignalR (inclusive métodos de hub), Blazor (`AuthorizeRouteView`), workers |
| Provedores de identidade | Qualquer servidor OpenID Connect com tokens assimétricos (RS\*/PS\*/ES\*); o `Authority` define a nuvem (inclusive as soberanas do Entra ID) |
| Sistemas | Windows, Linux e macOS; containers e Kubernetes |

## 🛡️ Segurança

Zero Trust: todo token é validado por inteiro (algoritmos só RS\*/PS\*/ES\*, emissor exato, audiência, validade de 30 s de
tolerância), claims `tec_*` do provedor são descartados, o tenant vem só do cadastro, as respostas não revelam o motivo da
recusa e nenhum token, segredo ou dado pessoal vai para log, trace ou métrica.

> [!CAUTION]
> Autorização não isola dados: filtre as consultas pelo `TenantId` da identidade. O componente também **não** faz rate
> limiting: use o `RateLimiter` do ASP.NET Core ou o gateway. Modelo de ameaças e checklist:
> [docs/seguranca.md](docs/seguranca.md). Vulnerabilidades: não abra *issue* pública; escreva para
> [roberto@roberto.inf.br](mailto:roberto@roberto.inf.br).

## 🧪 Testes

```bash
dotnet test --project TEC.Security.Tests -c Release --treenode-filter "/*/*/*/*[Category!=Integracao]"       # unitários
dotnet test --project TEC.Security.LoadTests -c Release --treenode-filter "/*/*/*/*[Category=Carga-CI]"      # carga rápida
```

309 testes unitários em `TEC.Security.Tests` (TUnit + FsCheck: ponta a ponta, fuzzing, DoS, vazamento, tempo
constante), 8 de carga rápida (`Carga-CI`, no PR e no release junto dos unitários), 3 `Seguranca-Pesada` e 6
`Carga-Pesada`, estes dois grupos só sob demanda no `performance.yml` manual. Ainda não há testes de integração com um
provedor de identidade real (a categoria `Integracao` está reservada). Para testar a **sua** API, use o
`TEC.Security.Testing`. Detalhes em [docs/testes.md](docs/testes.md).

## 🤝 Contribuição

Branch a partir da `main` → código **e** testes (inclusive entradas hostis) → `dotnet test` (também sem ICU) → CHANGELOG e
`docs/` atualizados → pull request com o check `ci / ci-ok` verde. Como compilar (credencial do feed `tec-interno`,
modo local com `-p:TecUseLocalProjects=true`): [docs/desenvolvimento.md](docs/desenvolvimento.md).

## 🏷️ Versionamento

[SemVer](https://semver.org/lang/pt-BR/), uma versão para os quatro pacotes (`Directory.Build.props`). Enquanto for `0.x`,
mudanças incompatíveis podem ocorrer em versões MINOR; um membro novo em interface (`ISecurityUser`, `ITenantRegistry`,
`IPermissionStore`, `IAccessTokenProvider`) ou uma validação que recusa configuração antes aceita contam como incompatíveis.
Cada merge na `main` publica a prévia `<Version>-preview.N`; versões estáveis e `-rc.N` saem só pelo workflow
**Publicar versão** ([CI/CD](.github/workflows/README.md)).

## 📄 Licença

[Apache 2.0](LICENSE) — consulte [NOTICE](NOTICE) para informações de atribuição. Criado e mantido por **Roberto Oliveira**, equipe **Tudo em Código** · [github.com/tudoemcodigo](https://github.com/tudoemcodigo)
