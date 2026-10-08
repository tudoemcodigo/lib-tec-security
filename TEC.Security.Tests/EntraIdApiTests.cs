using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.EntraId;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>
/// Provedor Entra ID com tokens no formato real (v2.0), assinados por uma chave local no lugar do JWKS: emissor por tenant,
/// tenants do cadastro com recarga, ID token, aplicações cliente e versão do token.
/// </summary>
public class EntraIdApiTests
{
    private const string HomeTenant = "aaaaaaaa-0000-0000-0000-00000000000a";
    private const string CustomerTenant = "bbbbbbbb-0000-0000-0000-00000000000b";
    private const string OtherTenant = "cccccccc-0000-0000-0000-00000000000c";
    private const string ApiClientId = "dddddddd-0000-0000-0000-00000000000d";
    private const string FrontClientId = "eeeeeeee-0000-0000-0000-00000000000e";

    private sealed class EntraTokens : IDisposable
    {
        private readonly RSA _rsa = RSA.Create(2048);

        public EntraTokens() => Key = new RsaSecurityKey(_rsa) { KeyId = "entra-teste" };

        public RsaSecurityKey Key { get; }

        public string Create(string tenant, Action<Dictionary<string, object>>? configure = null, string? issuer = null, string audience = ApiClientId)
        {
            var claims = new Dictionary<string, object>
            {
                ["ver"] = "2.0",
                ["tid"] = tenant,
                ["oid"] = "0f0f0f0f-0000-0000-0000-000000000001",
                ["sub"] = "pairwise-sub",
                ["azp"] = FrontClientId,
                ["scp"] = "access_as_user",
                ["name"] = "Ana Teste",
                ["roles"] = new[] { "pedidos:ler" }
            };
            configure?.Invoke(claims);

            return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = issuer ?? $"https://login.microsoftonline.com/{tenant}/v2.0",
                Audience = audience,
                Claims = claims,
                Expires = DateTime.UtcNow.AddMinutes(10),
                SigningCredentials = new SigningCredentials(Key, SecurityAlgorithms.RsaSha256)
            });
        }

        public void Dispose() => _rsa.Dispose();
    }

    private static async Task<(TestApp App, EntraTokens Tokens)> StartAsync(Action<EntraIdApiOptions>? configure = null,
        Dictionary<string, string?>? config = null)
    {
        var tokens = new EntraTokens();
        var configuration = new Dictionary<string, string?>
        {
            ["Security:Tenants:cliente-b:IdentityProviders:EntraId:0"] = CustomerTenant,
            ["Security:Tenants:cliente-c:Enabled"] = "false",
            ["Security:Tenants:cliente-c:IdentityProviders:EntraId:0"] = OtherTenant
        };
        foreach (var (key, value) in config ?? [])
            configuration[key] = value;

        var app = await TestApp.StartAsync(
            builder => builder.Services.AddTecSecurity(builder.Configuration, security =>
            {
                security.AddAspNetCore();
                EntraIdExtensions.AddEntraIdApiCore(security, "Funcionarios", o =>
                {
                    o.TenantId = HomeTenant;
                    o.ClientId = ApiClientId;
                    o.MultiTenant = true;
                    configure?.Invoke(o);
                }, [tokens.Key]);
            }),
            app =>
            {
                app.MapGet("/eu", (ISecurityUser u) => $"{u.Kind}|{u.Id}|{u.TenantId}|{u.ExternalTenantId}|{u.ClientId}|{string.Join(',', u.Scopes)}");
                app.MapGet("/pedidos", () => "ok").RequireTecAuthorization(permissions: "pedidos:ler", schemes: "Funcionarios");
            },
            configuration);

        return (app, tokens);
    }

    private static Task<HttpResponseMessage> CallAsync(TestApp app, string path, string token) =>
        app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Get, path) { Headers = { Authorization = new AuthenticationHeaderValue("Bearer", token) } });

    [Test]
    public async Task User_token_of_registered_tenant_is_normalized()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;

        var response = await CallAsync(app, "/eu", tokens.Create(CustomerTenant));

        await Assert.That(await response.Content.ReadAsStringAsync())
            .IsEqualTo($"User|0f0f0f0f-0000-0000-0000-000000000001|cliente-b|{CustomerTenant}|{FrontClientId}|access_as_user");
        await Assert.That((await CallAsync(app, "/pedidos", tokens.Create(CustomerTenant))).StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Unregistered_or_inactive_tenant_is_rejected()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;

        var inactive = await CallAsync(app, "/eu", tokens.Create(OtherTenant));
        var unknown = await CallAsync(app, "/eu", tokens.Create("ffffffff-0000-0000-0000-00000000000f"));

        await Assert.That(inactive.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(unknown.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Tenant_enabled_in_appsettings_applies_without_restart()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;
        string token = tokens.Create(OtherTenant);

        var before = await CallAsync(app, "/eu", token);
        app.App.Configuration["Security:Tenants:cliente-c:Enabled"] = "true";
        ((IConfigurationRoot)app.App.Configuration).Reload();
        var after = await CallAsync(app, "/eu", token);

        await Assert.That(before.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(after.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Issuer_of_a_tenant_other_than_tid_is_rejected()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;

        // tid de um tenant liberado, mas emitido (iss) por outro tenant
        string token = tokens.Create(CustomerTenant, issuer: $"https://login.microsoftonline.com/{OtherTenant}/v2.0");

        await Assert.That((await CallAsync(app, "/eu", token)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task ID_token_without_scp_or_roles_is_rejected_as_access_token()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;
        string idToken = tokens.Create(HomeTenant, c => { c.Remove("scp"); c.Remove("roles"); c["nonce"] = "abc"; });

        await Assert.That((await CallAsync(app, "/eu", idToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task ID_token_with_roles_does_not_become_application_identity()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;

        // ID token real: aud = client id, roles do usuário, sem scp, sem azp, com nonce, sub pairwise != oid
        string idToken = tokens.Create(HomeTenant, c => { c.Remove("scp"); c.Remove("azp"); c["nonce"] = "n"; });
        string withoutAzp = tokens.Create(HomeTenant, c => c.Remove("azp"));
        string withoutScpOrIdtyp = tokens.Create(HomeTenant, c => c.Remove("scp"));   // sub != oid e sem idtyp
        string appBySub = tokens.Create(HomeTenant, c => { c.Remove("scp"); c["sub"] = c["oid"]; });

        await Assert.That((await CallAsync(app, "/eu", idToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await CallAsync(app, "/eu", withoutAzp)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await CallAsync(app, "/eu", withoutScpOrIdtyp)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(await (await CallAsync(app, "/eu", appBySub)).Content.ReadAsStringAsync()).StartsWith("Application|");
    }

    [Test]
    public async Task Client_application_outside_the_list_is_rejected()
    {
        var (app, tokens) = await StartAsync(o => o.AllowedClientApplications.Add(FrontClientId));
        await using var _ = app;
        using var __ = tokens;

        var allowed = await CallAsync(app, "/eu", tokens.Create(HomeTenant));
        var other = await CallAsync(app, "/eu", tokens.Create(HomeTenant, c => c["azp"] = "99999999-0000-0000-0000-000000000009"));

        await Assert.That(allowed.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(other.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task V1_token_is_rejected_by_default()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;
        string v1 = tokens.Create(HomeTenant, c => c["ver"] = "1.0", issuer: $"https://sts.windows.net/{HomeTenant}/", audience: $"api://{ApiClientId}");

        await Assert.That((await CallAsync(app, "/eu", v1)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Application_token_is_Application_identity_and_can_be_blocked()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;
        string appToken = tokens.Create(HomeTenant, c => { c.Remove("scp"); c["idtyp"] = "app"; });

        string body = await (await CallAsync(app, "/eu", appToken)).Content.ReadAsStringAsync();

        await Assert.That(body).StartsWith("Application|");

        var (blocked, tokens2) = await StartAsync(o => o.AllowApplicationTokens = false);
        await using var ___ = blocked;
        using var ____ = tokens2;
        string blockedToken = tokens2.Create(HomeTenant, c => { c.Remove("scp"); c["idtyp"] = "app"; });
        await Assert.That((await CallAsync(blocked, "/eu", blockedToken)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Audience_of_another_API_is_rejected()
    {
        var (app, tokens) = await StartAsync();
        await using var _ = app;
        using var __ = tokens;

        var response = await CallAsync(app, "/eu", tokens.Create(HomeTenant, audience: "99999999-0000-0000-0000-000000000009"));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    // ---------------------------------------------------------------- configuração

    [Test]
    [Arguments("https://login.microsoftonline.com.evil.com/")]
    [Arguments("http://login.microsoftonline.com/")]
    [Arguments("https://login.microsoftonline.com/common/")]
    [Arguments("https://login.microsoftonline.com:8443/")]
    [Arguments("https://evil.com/")]
    public async Task Unofficial_instance_prevents_startup(string instance) =>
        await Assert.That(() => Register(o => o.Instance = instance)).Throws<InvalidOperationException>();

    [Test]
    public async Task TenantId_common_or_missing_without_MultiTenant_prevents_startup()
    {
        await Assert.That(() => Register(o => o.TenantId = "common")).Throws<InvalidOperationException>();
        await Assert.That(() => Register(o => { o.TenantId = null; o.MultiTenant = false; })).Throws<InvalidOperationException>();
        await Assert.That(() => Register(o => { o.MultiTenant = false; o.AllowedTenantIds.Add(CustomerTenant); })).Throws<InvalidOperationException>();
        await Assert.That(() => Register(o => o.ClientId = "minha-api")).Throws<InvalidOperationException>();
    }

    private static void Register(Action<EntraIdApiOptions> configure)
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        services.AddTecSecurity(new ConfigurationBuilder().Build(), security => security.AddAspNetCore().AddEntraIdApi("Entra", o =>
        {
            o.TenantId = HomeTenant;
            o.ClientId = ApiClientId;
            configure(o);
        }));
    }
}
