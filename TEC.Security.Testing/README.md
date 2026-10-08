<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-security/main/Images/Logo.png" alt="TEC.Security" width="100" />

# 🧪 TEC.Security.Testing

**Testa APIs protegidas pelo TEC.Security sem provedor de identidade real: tokens assinados com usuário, tenant, papéis e escopos sob medida.**

[📚 Documentação de testes](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/testes.md#testando-a-sua-api) · [📚 TEC.Security](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-security)

</div>

## ✨ O que é

- `TestTokenIssuer`: gera um par de chaves RSA 2048 **na memória** do processo de teste (nada vai para o disco) e emite JWTs
  RS256 com `TestTokenDescriptor` (`Subject`, `ExternalTenantId`, `Name`, `IsApplication`, `Roles`, `Scopes`,
  `ExtraClaims`, `Lifetime`, `IssuedAt`, `Audience`, `Issuer`). Aceita um `TimeProvider` para relógio controlado.
- `AddTestJwt(emissor)`: registra o provedor `Test`, validado com as **mesmas** regras endurecidas dos provedores reais.
- Falha fechada: a aplicação **não sobe** fora dos ambientes `Development`, `Testing` e `Test`, então um provedor de teste
  esquecido no `Program.cs` nunca vale em produção.

## 🎯 Quando usar

Em projetos de teste de integração (ex.: `WebApplicationFactory`) da **sua** API, para simular usuários, aplicações,
tenants, papéis e escopos, e casos de erro (token expirado, de outra audiência, com `tec_perm` injetado).

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Security.Testing --version 0.0.1
```

Instale só no projeto de testes. O feed do GitHub Packages exige um PAT *classic* com `read:packages`.

## 🚀 Início rápido

```csharp
using TEC.Security.AspNetCore;
using TEC.Security.DependencyInjection;
using TEC.Security.Testing;

// Program.cs (ambiente "Testing"): o emissor vem dos testes
builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddAspNetCore()
    .AddTestJwt(Program.TestIssuer!));

// No teste
using var emissor = new TestTokenIssuer();               // emissor e audiência padrão
string token = emissor.CreateToken(t =>
{
    t.ExternalTenantId = "tenant-de-teste";              // Security:Tenants:*:IdentityProviders:Test
    t.Roles.Add("Gerente");
    t.Scopes.Add("access_as_user");
});
client.DefaultRequestHeaders.Authorization = new("Bearer", token);
```

`CreateToken` depois do `Dispose` lança `ObjectDisposedException`; emissor ou audiência vazios lançam `ArgumentException`.

## 📚 Documentação

[Testando a sua API](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/testes.md#testando-a-sua-api) ·
[Autorização](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/autorizacao.md) ·
[Tenants](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/tenants.md)

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-security/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
