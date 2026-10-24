using System.Net.Http.Headers;
using BenchmarkDotNet.Attributes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.Testing;

namespace TEC.Security.Benchmarks;

/// <summary>
/// Requisição completa no pipeline do ASP.NET Core (TestServer, sem rede): seleção do esquema, validação do JWT ou da API key,
/// normalização, autorização por permissão e respostas 401/403 padronizadas. Mede o custo que o TEC.Security soma a cada
/// requisição.
/// </summary>
[MemoryDiagnoser]
public class HttpPipelineBenchmarks
{
    private const string Tid = "11111111-1111-1111-1111-111111111111";

    private WebApplication _app = null!;
    private HttpClient _client = null!;
    private TestTokenIssuer _issuer = null!;
    private string _authorized = string.Empty;
    private string _forbidden = string.Empty;
    private string _otherKey = string.Empty;
    private string _apiKey = string.Empty;

    [GlobalSetup]
    public void Setup()
    {
        _issuer = new TestTokenIssuer();
        var key = ApiKeyGenerator.Generate("erp-contoso");
        _apiKey = key.Key;

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:Tenants:contoso:IdentityProviders:Test:0"] = Tid,
            ["Security:Permissions:Roles:Gerente:0"] = "pedidos:ler",
            ["Security:ApiKeys:Keys:erp-contoso:Hash"] = key.Hash,
            ["Security:ApiKeys:Keys:erp-contoso:TenantId"] = "contoso",
            ["Security:ApiKeys:Keys:erp-contoso:Permissions:0"] = "pedidos:ler",
            ["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = DateTimeOffset.UtcNow.AddYears(1).ToString("O")
        });
        builder.Services.AddTecSecurity(builder.Configuration, security => security.AddAspNetCore().AddApiKeys().AddTestJwt(_issuer));

        _app = builder.Build();
        _app.MapGet("/publico", () => "ok").AllowAnonymous();
        _app.MapGet("/pedidos", () => "lista").RequireTecAuthorization(permissions: "pedidos:ler");
        _app.StartAsync().GetAwaiter().GetResult();

        _client = _app.GetTestClient();
        _client.BaseAddress = new Uri("https://localhost/");

        // Tokens com validade longa: o benchmark inteiro usa os mesmos
        _authorized = _issuer.CreateToken(t => { t.ExternalTenantId = Tid; t.Roles.Add("Gerente"); t.Lifetime = TimeSpan.FromHours(2); });
        _forbidden = _issuer.CreateToken(t => { t.ExternalTenantId = Tid; t.Lifetime = TimeSpan.FromHours(2); });
        using var other = new TestTokenIssuer();
        _otherKey = other.CreateToken(t => { t.ExternalTenantId = Tid; t.Lifetime = TimeSpan.FromHours(2); });
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _client.Dispose();
        _app.StopAsync().GetAwaiter().GetResult();
        _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _issuer.Dispose();
    }

    [Benchmark(Baseline = true)]
    public Task<int> Anonymous() => SendAsync("/publico");

    [Benchmark]
    public Task<int> JwtAuthorized() => SendAsync("/pedidos", bearer: _authorized);

    [Benchmark]
    public Task<int> JwtForbidden() => SendAsync("/pedidos", bearer: _forbidden);

    [Benchmark]
    public Task<int> JwtWrongSignature() => SendAsync("/pedidos", bearer: _otherKey);

    [Benchmark]
    public Task<int> ApiKeyAuthorized() => SendAsync("/pedidos", apiKey: _apiKey);

    [Benchmark]
    public Task<int> NoCredentials() => SendAsync("/pedidos");

    private async Task<int> SendAsync(string path, string? bearer = null, string? apiKey = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (bearer is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        if (apiKey is not null)
            request.Headers.Add("X-Api-Key", apiKey);

        using var response = await _client.SendAsync(request);
        await response.Content.ReadAsByteArrayAsync();
        return (int)response.StatusCode;
    }
}
