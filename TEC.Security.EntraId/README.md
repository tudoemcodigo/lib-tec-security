<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-security/main/Images/Logo.png" alt="TEC.Security" width="100" />

# 🪪 TEC.Security.EntraId

**Provedor Microsoft Entra ID do TEC.Security: APIs, login web, chamadas entre serviços e On-Behalf-Of, com tenants liberados por configuração e nenhum segredo na aplicação.**

[📚 Documentação do provedor](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/provedor-entra-id.md) · [📚 TEC.Security](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-security)

</div>

## ✨ O que é

| Recurso | Método |
|---|---|
| API protegida: RS256, emissor exato do tenant, audiência, `scp`/`roles` obrigatórios (ID token recusado), aplicações cliente permitidas | `AddEntraIdApi` |
| Login web (MVC, Razor Pages, Blazor): Authorization Code + PKCE, cookie `__Host-`, sessão revalidada | `AddEntraIdWebLogin` + `MapTecWebLogin` |
| Chamadas entre serviços (client credentials) e On-Behalf-Of, só para `AllowedHosts` com HTTPS | `AddEntraIdClient`, `AddEntraIdAccessToken`, `AddEntraIdOnBehalfOf` |
| Multi-tenant: só os tenants **ativos** no cadastro (`Security:Tenants`), com recarga | `MultiTenant = true` |

| Credencial (`Credential:Type`) | Segredo na aplicação? |
|---|---|
| `ManagedIdentityFederation` (padrão, Azure) · `WorkloadIdentity` (AKS, GitHub OIDC) | Nenhum |
| `Certificate` | Nenhum: a client assertion é assinada **dentro** do cofre (TEC.Vault); a chave pode ser não exportável |
| `ClientSecret` | No cofre, relido a cada 30 min (último recurso) |
| `ManagedIdentity` · `Developer` (só Development) | Só para chamadas entre serviços |

## 🎯 Quando usar

Em aplicações que autenticam usuários ou serviços no Microsoft Entra ID (nuvem pública, US Gov ou China).

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Security.EntraId --version 0.0.1
```

O feed do GitHub Packages exige um PAT *classic* com `read:packages`. O pacote traz `TEC.Security.AspNetCore`,
`TEC.Security` e `TEC.Vault`.

## 🚀 Início rápido

```json
{
  "Security": {
    "EntraId": {
      "Api": { "TenantId": "<tenant-id>", "ClientId": "<client-id-da-api>", "AllowedClientApplications": [ "<client-id-do-front>" ] }
    },
    "Permissions": { "Roles": { "Gerente": [ "pedidos:ler", "pedidos:cancelar" ] } }
  }
}
```

```csharp
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.EntraId;

builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddAspNetCore()
    .AddEntraIdApi("Funcionarios", builder.Configuration.GetSection("Security:EntraId:Api")));

var app = builder.Build();
app.MapGet("/pedidos", () => "ok").RequireTecAuthorization(permissions: "pedidos:ler");
app.Run();
```

Opções inválidas (instância não oficial, `TenantId` ausente ou `common`, credencial `Developer` fora de Development...)
impedem a subida.

## 📚 Documentação

[Provedor Entra ID](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/provedor-entra-id.md) ·
[Chamadas entre serviços](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/chamadas-entre-servicos.md) ·
[Tenants](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/tenants.md) ·
[Autorização](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/autorizacao.md) ·
[Segurança](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/seguranca.md)

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-security/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
