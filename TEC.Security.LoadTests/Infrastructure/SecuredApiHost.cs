using System.Globalization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.Testing;

namespace TEC.Security.LoadTests.Infrastructure;

/// <summary>
/// API protegida pelo TEC.Security, hospedada no próprio processo em Kestrel real (sockets TCP em 127.0.0.1, porta livre
/// escolhida pelo SO): JWT (emissor de teste, mesmas regras endurecidas dos provedores reais), API key e permissões vindas de
/// um store que simula o banco, com o cache padrão de 5 minutos.
/// </summary>
public sealed class SecuredApiHost : IAsyncDisposable
{
    /// <summary>Tenant externo (claim <c>tid</c>) cadastrado como <c>contoso</c>.</summary>
    public const string Tid = "11111111-1111-1111-1111-111111111111";

    /// <summary>Permissão exigida por <c>GET /pedidos</c> (concedida pelo store ao papel <c>pedidos</c>).</summary>
    public const string Permission = "pedidos:executar";

    private readonly WebApplication _app;

    private SecuredApiHost(WebApplication app, TestTokenIssuer issuer, GeneratedApiKey apiKey, Uri baseAddress)
    {
        _app = app;
        Issuer = issuer;
        ApiKey = apiKey;
        BaseAddress = baseAddress;
    }

    /// <summary>Endereço da API (ex.: http://127.0.0.1:53817/).</summary>
    public Uri BaseAddress { get; }

    /// <summary>Emissor dos tokens aceitos.</summary>
    public TestTokenIssuer Issuer { get; }

    /// <summary>API key cadastrada (tenant <c>contoso</c>, permissão <see cref="Permission"/>).</summary>
    public GeneratedApiKey ApiKey { get; }

    /// <summary>Store de permissões (conta as consultas que o cache não evitou).</summary>
    public SimulatedDatabasePermissionStore PermissionStore => _app.Services.GetRequiredService<SimulatedDatabasePermissionStore>();

    /// <summary>Inicia a API.</summary>
    /// <param name="permissionLatency">Latência simulada de cada consulta de permissões ao "banco".</param>
    public static async Task<SecuredApiHost> StartAsync(TimeSpan? permissionLatency = null)
    {
        var issuer = new TestTokenIssuer();
        var apiKey = ApiKeyGenerator.Generate("erp-contoso");

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.Logging.ClearProviders();
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:RequireTenant"] = "true",
            ["Security:Tenants:contoso:IdentityProviders:Test:0"] = Tid,
            ["Security:ApiKeys:Keys:erp-contoso:Hash"] = apiKey.Hash,
            ["Security:ApiKeys:Keys:erp-contoso:TenantId"] = "contoso",
            ["Security:ApiKeys:Keys:erp-contoso:Permissions:0"] = Permission,
            ["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = DateTimeOffset.UtcNow.AddDays(1).ToString("O", CultureInfo.InvariantCulture)
        });

        // Depois de limpar as fontes da configuração: o UseUrls grava o endereço nela (limpar depois voltaria para a porta 5000)
        builder.WebHost.UseUrls("http://127.0.0.1:0");

        builder.Services.AddSingleton(new PermissionStoreLatency(permissionLatency ?? TimeSpan.Zero));
        builder.Services.AddTecSecurity(builder.Configuration, security => security
            // Kestrel de teste sem TLS: em produção a API key exige HTTPS (padrão)
            .AddAspNetCore(o => o.ApiKeyRequiresHttps = false)
            .AddApiKeys()
            .AddTestJwt(issuer)
            .UsePermissionStore<SimulatedDatabasePermissionStore>());

        var app = builder.Build();
        app.MapGet("/publico", () => "ok").AllowAnonymous();
        app.MapGet("/pedidos", (ISecurityUser user) => user.Id).RequireTecAuthorization(permissions: Permission);
        app.MapDelete("/pedidos", () => "cancelado").RequireTecAuthorization(permissions: Permission, kinds: TecPrincipalKinds.User);

        await app.StartAsync();
        return new SecuredApiHost(app, issuer, apiKey, new Uri(app.Urls.First()));
    }

    /// <summary>Cliente HTTP com uma conexão por worker.</summary>
    public HttpClient CreateClient(int concurrency) =>
        new(new SocketsHttpHandler { MaxConnectionsPerServer = concurrency }, disposeHandler: true)
        {
            BaseAddress = BaseAddress,
            Timeout = TimeSpan.FromSeconds(30)
        };

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        Issuer.Dispose();
    }
}
