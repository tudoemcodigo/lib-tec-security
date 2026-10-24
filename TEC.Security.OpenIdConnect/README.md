<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Security" width="100" />

# 🌐 TEC.Security.OpenIdConnect

**Provedor agnóstico de autenticação e autorização OpenID Connect e OAuth 2.0 para .NET 8 e 10.**

Keycloak · Auth0 · Okta · Microsoft Entra ID (OIDC) · Google Identity · AWS Cognito · Validação JWT endurecida · M2M Client Credentials · Login Web com PKCE

</div>

---

## 📑 Sumário

- [Visão Geral](#-visão-geral)
- [Instalação](#-instalação)
- [Cenário 1: Protegendo APIs REST (Tokens Bearer)](#-cenário-1-protegendo-apis-rest-tokens-bearer)
- [Cenário 2: Chamadas Entre Serviços (M2M Client Credentials)](#-cenário-2-chamadas-entre-serviços-m2m-client-credentials)
- [Cenário 3: Login Web (Authorization Code + PKCE)](#-cenário-3-login-web-authorization-code--pkce)
- [Compatibilidade](#-compatibilidade)

---

## 🧭 Visão Geral

O `TEC.Security.OpenIdConnect` é a implementação universal de autenticação e autorização baseada nos padrões abertos OpenID Connect Core 1.0 e OAuth 2.0 (RFC 6749). Com ele, sua aplicação não fica refém de nenhuma nuvem proprietária: o mesmo código funciona com **Keycloak**, **Auth0**, **Okta**, **AWS Cognito** ou **Microsoft Entra ID**.

---

## 📥 Instalação

```bash
dotnet add package TEC.Security.OpenIdConnect
```

---

## 🚀 Cenário 1: Protegendo APIs REST (Tokens Bearer)

Protege endpoints ASP.NET Core validando tokens emitidos por qualquer provedor OIDC (ex.: Keycloak).

```csharp
builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddAspNetCore()
    .AddOpenIdConnectApi("Keycloak", options =>
    {
        options.Authority = "https://auth.empresa.com/realms/corporativo";
        options.Audience = "api-pedidos";
    }));

var app = builder.Build();

app.MapGet("/pedidos", () => "Acesso autorizado")
   .RequireTecAuthorization("pedidos.ler");
```

---

## 🤖 Cenário 2: Chamadas Entre Serviços (M2M Client Credentials)

Para microsserviços ou workers que precisam chamar outras APIs autenticadas:

```csharp
builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddOpenIdConnectClient(options =>
    {
        options.Authority = "https://auth.empresa.com/realms/corporativo";
        options.ClientId = "servico-faturamento";
        options.ClientSecretName = "segredo-faturamento"; // Busca segura no TEC.Vault
    }));

builder.Services.AddHttpClient("ApiEstoque", client =>
{
    client.BaseAddress = new Uri("https://estoque.empresa.com/");
})
.AddOpenIdConnectAccessToken(options =>
{
    options.Scopes.Add("estoque.consultar");
    options.AllowedHosts.Add("estoque.empresa.com"); // Proteção estrita contra SSRF
});
```

---

## 🖥️ Cenário 3: Login Web (Authorization Code + PKCE)

Para aplicações web, Blazor Server ou Razor Pages:

```csharp
builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddAspNetCore()
    .AddOpenIdConnectWebLogin("WebAuth", options =>
    {
        options.Authority = "https://auth.empresa.com/realms/corporativo";
        options.ClientId = "portal-web";
        options.ClientSecretName = "portal-web-secret";
        options.Scopes.Add("email");
    }));
```

---

## ⚡ Compatibilidade

- **Runtimes:** .NET 8.0 (LTS) e .NET 10.0 (LTS)
- **Compilação:** Compatível com **Native AOT** e **Trimming**
- **Licença:** MIT
