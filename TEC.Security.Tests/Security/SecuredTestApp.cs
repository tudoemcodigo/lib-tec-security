using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.Testing;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests.Security;

/// <summary>
/// API de referência dos testes de segurança (TestServer, sem rede): JWT de teste, API key, tenant ativo e inativo, permissão
/// por papel. Mesmo cadastro em todos os testes adversariais, para que as respostas possam ser comparadas entre si.
/// </summary>
internal sealed class SecuredTestApp : IAsyncDisposable
{
    public const string Tid = "11111111-1111-1111-1111-111111111111";
    public const string InactiveTid = "22222222-2222-2222-2222-222222222222";

    private SecuredTestApp(TestApp app, TestTokenIssuer issuer, GeneratedApiKey apiKey, GeneratedApiKey expiredKey)
    {
        App = app;
        Issuer = issuer;
        ApiKey = apiKey;
        ExpiredApiKey = expiredKey;
    }

    public TestApp App { get; }

    public HttpClient Client => App.Client;

    public TestTokenIssuer Issuer { get; }

    /// <summary>API key válida (tenant contoso, permissão pedidos:ler).</summary>
    public GeneratedApiKey ApiKey { get; }

    /// <summary>API key cadastrada, mas expirada.</summary>
    public GeneratedApiKey ExpiredApiKey { get; }

    /// <summary>Token válido com a permissão de <c>GET /pedidos</c>.</summary>
    public string ValidToken(Action<TestTokenDescriptor>? configure = null) => Issuer.CreateToken(t =>
    {
        t.Subject = "usuario-1";
        t.ExternalTenantId = Tid;
        t.Roles.Add("Gerente");
        configure?.Invoke(t);
    });

    public static async Task<SecuredTestApp> StartAsync(Action<SecurityAspNetCoreOptions>? aspNetCore = null, string environment = "Testing",
        bool requireTenant = true)
    {
        var issuer = new TestTokenIssuer();
        var apiKey = ApiKeyGenerator.Generate("erp-contoso");
        var expired = ApiKeyGenerator.Generate("erp-expirada");
        var configuration = new Dictionary<string, string?>
        {
            ["Security:RequireTenant"] = requireTenant ? "true" : "false",
            ["Security:Tenants:contoso:IdentityProviders:Test:0"] = Tid,
            ["Security:Tenants:inativo:Enabled"] = "false",
            ["Security:Tenants:inativo:IdentityProviders:Test:0"] = InactiveTid,
            ["Security:Permissions:Roles:Gerente:0"] = "pedidos:ler",
            ["Security:ApiKeys:Keys:erp-contoso:Hash"] = apiKey.Hash,
            ["Security:ApiKeys:Keys:erp-contoso:TenantId"] = "contoso",
            ["Security:ApiKeys:Keys:erp-contoso:Permissions:0"] = "pedidos:ler",
            ["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = DateTimeOffset.UtcNow.AddDays(1).ToString("O"),
            ["Security:ApiKeys:Keys:erp-expirada:Hash"] = expired.Hash,
            ["Security:ApiKeys:Keys:erp-expirada:TenantId"] = "contoso",
            ["Security:ApiKeys:Keys:erp-expirada:Permissions:0"] = "pedidos:ler",
            ["Security:ApiKeys:Keys:erp-expirada:ExpiresOn"] = DateTimeOffset.UtcNow.AddDays(-1).ToString("O")
        };

        var app = await TestApp.StartAsync(
            builder => builder.Services.AddTecSecurity(builder.Configuration, security => security
                .AddAspNetCore(o =>
                {
                    o.HubPaths.Add("/hubs/chat");
                    aspNetCore?.Invoke(o);
                })
                .AddApiKeys()
                .AddTestJwt(issuer)),
            app =>
            {
                app.MapGet("/publico", () => "ok").AllowAnonymous();
                app.MapGet("/pedidos", (ISecurityUser user) => $"{user.Kind}|{user.Id}|{user.TenantId}").RequireTecAuthorization(permissions: "pedidos:ler");
                app.MapDelete("/pedidos", () => "cancelado").RequireTecAuthorization(permissions: "pedidos:cancelar");
                app.MapGet("/hubs/chat/negotiate", () => "hub").RequireTecAuthorization();
            },
            configuration, environment);

        return new SecuredTestApp(app, issuer, apiKey, expired);
    }

    public async ValueTask DisposeAsync()
    {
        await App.DisposeAsync();
        Issuer.Dispose();
    }
}
