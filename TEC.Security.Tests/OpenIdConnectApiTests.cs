using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect;
using TEC.Security.Testing;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

public class OpenIdConnectApiTests
{
    private const string Issuer = "https://auth.empresa.com/realms/corporativo";
    private const string Audience = "api-pedidos";

    [Test]
    public async Task Token_from_OpenIdConnect_is_accepted_and_normalized()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, Audience);

        await using var app = await CreateAppAsync(security =>
        {
            security.AddAspNetCore();
        }, testIssuer.SigningKey);

        string token = testIssuer.CreateToken(d =>
        {
            d.Subject = "user-123";
            d.Name = "Maria Silva";
            d.Roles.Add("vendedor");
            d.Roles.Add("financeiro");
            d.Scopes.Add("pedidos.ler");
            d.Scopes.Add("pedidos.criar");
        });

        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        using var response = await app.Client.SendAsync(request);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);

        string body = await response.Content.ReadAsStringAsync();
        await Assert.That(body).Contains("user-123");
        await Assert.That(body).Contains("Maria Silva");
        await Assert.That(body).Contains("vendedor");
    }

    [Test]
    public async Task Keycloak_nested_realm_roles_are_extracted_correctly()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, Audience);

        await using var app = await CreateAppAsync(security =>
        {
            security.AddAspNetCore();
        }, testIssuer.SigningKey);

        // Keycloak envia roles em objeto JSON realm_access: { roles: [...] }
        string token = testIssuer.CreateToken(d =>
        {
            d.Subject = "admin-456";
            d.Name = "Admin Sistema";
            d.ExtraClaims["realm_access"] = """{"roles":["administrador","auditor"]}""";
        });

        using var request = new HttpRequestMessage(HttpMethod.Get, "/admin-only");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        using var response = await app.Client.SendAsync(request);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Wrong_audience_is_rejected_with_401()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, "outra-api");

        await using var app = await CreateAppAsync(security =>
        {
            security.AddAspNetCore();
        }, testIssuer.SigningKey);

        string token = testIssuer.CreateToken(d => d.Subject = "user-123");

        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

        using var response = await app.Client.SendAsync(request);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task AllowedHosts_enforces_port_restrictions_SEC14()
    {
        var options = new TEC.Security.Tokens.AccessTokenHandlerOptions
        {
            Scopes = { "pedidos.ler" },
            AllowedHosts = { "api.contoso.com", "parceiro.com:8443" }
        };
        options.Validate();

        // Host padrão 443 liberado
        await Assert.That(options.IsAllowedDestination(new Uri("https://api.contoso.com/pedidos"))).IsTrue();
        await Assert.That(options.IsAllowedDestination(new Uri("https://api.contoso.com:443/pedidos"))).IsTrue();

        // Porta não autorizada no mesmo host deve ser bloqueada!
        await Assert.That(options.IsAllowedDestination(new Uri("https://api.contoso.com:9090/metrics"))).IsFalse();
        await Assert.That(options.IsAllowedDestination(new Uri("https://api.contoso.com:8443/pedidos"))).IsFalse();

        // Host com porta explícita configurada deve aceitar apenas essa porta
        await Assert.That(options.IsAllowedDestination(new Uri("https://parceiro.com:8443/v1"))).IsTrue();
        await Assert.That(options.IsAllowedDestination(new Uri("https://parceiro.com/v1"))).IsFalse();
        await Assert.That(options.IsAllowedDestination(new Uri("https://parceiro.com:443/v1"))).IsFalse();
    }

    private static Task<TestApp> CreateAppAsync(Action<SecurityBuilder> configureSecurity, SecurityKey signingKey)
    {
        return TestApp.StartAsync(
            builder =>
            {
                builder.Services.AddTecSecurity(new ConfigurationBuilder().Build(), security =>
                {
                    configureSecurity(security);
                    TEC.Security.OpenIdConnect.OpenIdConnectExtensions.AddOpenIdConnectApiCore(security, "Keycloak", options =>
                    {
                        options.Authority = Issuer;
                        options.Audience = Audience;
                    }, [signingKey]);
                });
            },
            app =>
            {
                app.UseAuthentication();
                app.UseAuthorization();
                app.MapGet("/me", (ISecurityUser user) => Results.Ok(new
                {
                    user.Id,
                    user.Name,
                    Roles = user.Roles.ToArray()
                })).RequireTecAuthorization();

                app.MapGet("/admin-only", () => Results.Ok("OK"))
                    .RequireAuthorization(new TecAuthorizeAttribute { Roles = "administrador" });
            });
    }
}
