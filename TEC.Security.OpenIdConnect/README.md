<div align="center">

<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="TEC.Security" width="100" />

# 🌐 TEC.Security.OpenIdConnect

**Provedor agnóstico de autenticação e autorização OpenID Connect e OAuth 2.0 para .NET 10.**

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
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Security.OpenIdConnect --version 0.0.1
```

O feed do GitHub Packages exige um PAT *classic* com `read:packages`. O pacote traz `TEC.Security.AspNetCore`, `TEC.Security` e `TEC.Vault`.

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

O tipo da identidade (usuário ou aplicação) vem de regras do esquema, em `options.Kind`. Um token que nenhuma regra
reconhece é recusado (401), em vez de virar usuário por padrão. Para a conta de serviço do Keycloak, por exemplo:
`options.Kind.ApplicationClaims.Add("client_id=*")`. No Entra ID, a regra do `scp` já vem ligada. Detalhes e receitas por
IdP em [Tipo da identidade (Kind)](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/provedor-openid-connect.md#tipo-da-identidade-kind).

---

## 🤖 Cenário 2: Chamadas Entre Serviços (M2M Client Credentials)

Para microsserviços ou workers que precisam chamar outras APIs autenticadas:

```csharp
builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddOpenIdConnectClient(options =>
    {
        options.Authority = "https://auth.empresa.com/realms/corporativo";
        options.ClientId = "servico-faturamento";
        options.ClientSecretName = "segredo-faturamento"; // lido do TEC.Vault (registre o ISecretReader com AddTecVault)
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

As opções do cliente são validadas na subida da aplicação, e o `HttpClient` do endpoint de token não segue redirecionamentos
(o client secret vai no corpo do pedido). Um cliente M2M por aplicação.

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
        options.ClientSecretName = "portal-web-secret"; // conferido na subida e lido do TEC.Vault a cada login
        options.Scopes.Add("email");
    }));

var app = builder.Build();
app.MapTecWebLogin();   // GET /account/login?returnUrl=/ e POST /account/logout
```

---

## ⚡ Compatibilidade

- **Runtime:** .NET 10.0 (LTS)
- **Compilação:** Compatível com **Native AOT** e **Trimming**
- **Licença:** Apache 2.0
