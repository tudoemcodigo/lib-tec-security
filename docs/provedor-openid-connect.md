[🏠 TEC.Security](../README.md) › [📚 Documentação](README.md) › 🌐 Provedor OpenID Connect

# 🌐 Provedor OpenID Connect

O pacote **`TEC.Security.OpenIdConnect`** é o provedor agnóstico e universal do ecossistema TEC. Ele implementa os padrões abertos **OpenID Connect Core 1.0** e **OAuth 2.0 (RFC 6749)**, permitindo autenticação e autorização seguras contra qualquer servidor de identidade do mercado:

- **Keycloak** (On-Premise, Kubernetes, Docker ou Cloud)
- **Auth0** e **Okta**
- **Microsoft Entra ID** (via OIDC standard)
- **Google Identity**
- **AWS Cognito**

---

## 📑 Sumário

- [1. Protegendo APIs REST com Tokens Bearer](#1-protegendo-apis-rest-com-tokens-bearer)
- [2. Chamadas Entre Serviços M2M (Client Credentials)](#2-chamadas-entre-serviços-m2m-client-credentials)
- [3. Login Web Interativo (Authorization Code + PKCE)](#3-login-web-interativo-authorization-code--pkce)
- [4. Mapeamento Inteligente de Papéis (Keycloak e OIDC)](#4-mapeamento-inteligente-de-papéis-keycloak-e-oidc)
- [5. Multi-tenancy](#5-multi-tenancy)

---

## 1. Protegendo APIs REST com Tokens Bearer

No `Program.cs`:

```csharp
builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddAspNetCore()
    .AddOpenIdConnectApi("Keycloak", options =>
    {
        options.Authority = "https://auth.empresa.com/realms/corporativo";
        options.Audience = "api-pedidos";
    }));
```

No `appsettings.json`:
```json
{
  "Security": {
    "OpenIdConnect": {
      "Authority": "https://auth.empresa.com/realms/corporativo",
      "Audience": "api-pedidos"
    }
  }
}
```

Endpoints protegidos:
```csharp
app.MapGet("/pedidos", () => Results.Ok("Liberado"))
   .RequireTecAuthorization("pedidos.ler");
```

---

## 2. Chamadas Entre Serviços M2M (Client Credentials)

Para comunicação segura entre microsserviços via OAuth 2.0 Client Credentials (RFC 6749):

```csharp
builder.Services.AddTecSecurity(builder.Configuration, security => security
    .AddOpenIdConnectClient(options =>
    {
        options.Authority = "https://auth.empresa.com/realms/corporativo";
        options.ClientId = "servico-faturamento";
        options.ClientSecretName = "segredo-faturamento"; // Busca segura e com cache no TEC.Vault
    }));

builder.Services.AddHttpClient("EstoqueClient", client =>
{
    client.BaseAddress = new Uri("https://estoque.empresa.com/");
})
.AddOpenIdConnectAccessToken(options =>
{
    options.Scopes.Add("estoque.consultar");
    options.AllowedHosts.Add("estoque.empresa.com"); // Blindagem SSRF (SEC-14)
});
```

---

## 3. Login Web Interativo (Authorization Code + PKCE)

Para portais web, Blazor Server e MVC:

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

## 4. Mapeamento Inteligente de Papéis (Keycloak e OIDC)

O `TEC.Security.OpenIdConnect` extrai e normaliza automaticamente papéis e permissões vindos de diferentes estruturas:

- Array simples de claims: `roles: ["admin", "financeiro"]`
- Objeto aninhado do Keycloak: `realm_access: { "roles": ["admin"] }`
- Objeto de recursos do Keycloak: `resource_access: { "client-app": { "roles": [...] } }`

---

## 5. Multi-tenancy

Com `options.MultiTenant = true`, a validação do token confere dinamicamente o emissor ou o claim de tenant informado contra o `ITenantRegistry` da aplicação, rejeitando tokens de tenants desconhecidos ou desativados.
