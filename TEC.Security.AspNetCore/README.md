<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-security/main/Images/Logo.png" alt="TEC.Security" width="100" />

# 🌐 TEC.Security.AspNetCore

**Protege APIs e sites ASP.NET Core com vários provedores de login ao mesmo tempo: tudo fechado por padrão, um único atributo de autorização e respostas 401/403 padronizadas.**

[📚 Documentação](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-security)

</div>

## ✨ O que é

| Recurso | Detalhe |
|---|---|
| Escolha do provedor por requisição | Esquema padrão `TEC`: token bearer pelo emissor, header de API key, cookie do login web; credencial desconhecida → 401 (nunca anônima) |
| JWT endurecido | Emissor, audiência, validade e assinatura sempre validados; algoritmos só RS\*/PS\*/ES\*; tolerância de 30 s; controles conferidos na subida, depois de qualquer `PostConfigure` |
| Fechado por padrão | `DefaultPolicy` e `FallbackPolicy` exigem identidade normalizada; `[TecAuthorize]` + `[AllowAnonymous]` impede a subida |
| `[TecAuthorize]` | Permissões, papéis, escopos, tipos e esquemas; vale em controllers, Minimal APIs (`RequireTecAuthorization`), gRPC, hubs SignalR e Blazor |
| Respostas | 401/403 com o `ApiResponse` do TEC.Core, `no-store` e `traceId`; motivo só no log de auditoria |
| API keys e login web | `AddApiKeys()`; base OIDC + PKCE com cookie `__Host-` e sessão revalidada (`AddWebLoginProvider`, `MapTecWebLogin`) |

## 🎯 Quando usar

Em APIs e sites ASP.NET Core. Normalmente vem junto com um provedor (`TEC.Security.EntraId`); instale direto para usar só
API keys ou para escrever um provedor novo (`AddJwtBearerProvider`).

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Security.AspNetCore --version 0.0.1
```

O feed do GitHub Packages exige um PAT *classic* com `read:packages`. O pacote traz o `TEC.Security` junto.

## 🚀 Início rápido

```csharp
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;

builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddAspNetCore()
    .AddApiKeys());   // chaves em Security:ApiKeys (só o hash)

var app = builder.Build();

app.MapGet("/pedidos", () => "ok").RequireTecAuthorization(permissions: "pedidos:ler");
app.MapGet("/saude", () => "ok").AllowAnonymous();   // o resto já exige identidade

app.Run();
```

```csharp
using Microsoft.AspNetCore.Mvc;

[ApiController, Route("pedidos")]
[TecAuthorize(Permissions = "pedidos:ler")]
public sealed class PedidosController : ControllerBase
{
    [HttpDelete("{id:guid}"), TecAuthorize(Permissions = "pedidos:cancelar", Kinds = TecPrincipalKinds.User)]
    public IActionResult Cancelar(Guid id) => NoContent();
}
```

## 📚 Documentação

[Configuração](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/configuracao.md) ·
[Autorização](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/autorizacao.md) ·
[API keys](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/api-keys.md) ·
[Novo provedor](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/novo-provedor.md) ·
[Erros](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/erros.md) ·
[Segurança](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/seguranca.md)

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-security/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
