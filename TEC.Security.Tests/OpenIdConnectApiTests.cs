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
            d.ExtraClaims["sid"] = "sessao-1";   // sinal de usuário (sessão no IdP)
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
            d.ExtraClaims["sid"] = "sessao-2";
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

    // ---------------------------------------------------------------- Kind (usuário x aplicação), ponta a ponta

    [Test]
    public async Task Token_without_user_or_application_signal_is_rejected_by_default()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, Audience);
        await using var app = await CreateAppAsync(security => security.AddAspNetCore(), testIssuer.SigningKey);

        // Antes: chegava como User e passava em Kinds = User. Agora: tipo indeterminado, 401
        var response = await SendAsync(app, "/so-pessoas", testIssuer.CreateToken(d => d.Subject = "quem-sou-eu"));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(app.Logs.All).Contains("tipo da identidade indeterminado");
    }

    [Test]
    public async Task Unresolved_User_accepts_token_without_signals_when_configured()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, Audience);
        await using var app = await CreateAppAsync(security => security.AddAspNetCore(), testIssuer.SigningKey,
            o => o.Kind.Unresolved = OpenIdConnectUnresolvedKind.User);

        var response = await SendAsync(app, "/so-pessoas", testIssuer.CreateToken(d => d.Subject = "auth0|123"));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Entra_application_token_without_idtyp_never_passes_as_user()
    {
        const string EntraAuthority = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";
        using var testIssuer = new TestTokenIssuer(EntraAuthority, Audience);
        await using var app = await CreateAppAsync(security => security.AddAspNetCore(), testIssuer.SigningKey,
            o => o.Authority = EntraAuthority);

        // Token app-only do Entra ID sem o claim opcional idtyp: roles (app roles), sem scp, oid = sub
        string appToken = testIssuer.CreateToken(d =>
        {
            d.Subject = "22222222-2222-2222-2222-222222222222";
            d.Roles.Add("pedidos.ler.todos");
            d.ExtraClaims["oid"] = "22222222-2222-2222-2222-222222222222";
            d.ExtraClaims["azp"] = "33333333-3333-3333-3333-333333333333";
        });
        string userToken = testIssuer.CreateToken(d =>
        {
            d.Subject = "pairwise-sub-do-usuario";
            d.Scopes.Add("access_as_user");
        });

        var appOnUserEndpoint = await SendAsync(app, "/so-pessoas", appToken);
        var appOnAppEndpoint = await SendAsync(app, "/so-aplicacoes", appToken);
        var userOnUserEndpoint = await SendAsync(app, "/so-pessoas", userToken);
        var userOnAppEndpoint = await SendAsync(app, "/so-aplicacoes", userToken);

        await Assert.That(appOnUserEndpoint.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(appOnAppEndpoint.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(userOnUserEndpoint.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(userOnAppEndpoint.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- MultiTenant = true, ponta a ponta

    private const string ActiveTid = "aaaaaaaa-0000-0000-0000-000000000001";
    private const string InactiveTid = "aaaaaaaa-0000-0000-0000-000000000002";
    private const string UnknownTid = "aaaaaaaa-0000-0000-0000-000000000003";

    private static readonly Dictionary<string, string?> MultiTenantConfig = new()
    {
        ["Security:Tenants:contoso:IdentityProviders:OpenIdConnect:0"] = ActiveTid,
        ["Security:Tenants:fabrikam:Enabled"] = "false",
        ["Security:Tenants:fabrikam:IdentityProviders:OpenIdConnect:0"] = InactiveTid,
        ["Security:Permissions:Tenants:contoso:Roles:Gerente:0"] = "pedidos:ler"
    };

    [Test]
    public async Task MultiTenant_accepts_only_active_registered_tenant()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, Audience);
        await using var app = await CreateAppAsync(security => security.AddAspNetCore(), testIssuer.SigningKey,
            o => o.MultiTenant = true, MultiTenantConfig);

        string Token(string? tid) => testIssuer.CreateToken(d =>
        {
            d.Subject = "user-1";
            d.ExternalTenantId = tid;
            d.ExtraClaims["sid"] = "sessao-1";
        });

        var active = await SendAsync(app, "/tenant", Token(ActiveTid));
        var inactive = await SendAsync(app, "/tenant", Token(InactiveTid));
        var unknown = await SendAsync(app, "/tenant", Token(UnknownTid));
        var withoutTenant = await SendAsync(app, "/tenant", Token(null));   // sem tid: o iss é a chave, não cadastrada

        await Assert.That(active.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(await active.Content.ReadAsStringAsync()).IsEqualTo("contoso");
        await Assert.That(inactive.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(unknown.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(withoutTenant.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task MultiTenant_role_is_not_a_permission_by_default_but_per_tenant_mapping_applies()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, Audience);
        await using var app = await CreateAppAsync(security => security.AddAspNetCore(), testIssuer.SigningKey,
            o => o.MultiTenant = true, MultiTenantConfig);

        // O admin do tenant cliente atribuiu o papel "pedidos:cancelar": em multi-tenant ele não vira permissão
        string token = testIssuer.CreateToken(d =>
        {
            d.Subject = "user-1";
            d.ExternalTenantId = ActiveTid;
            d.Roles.Add("pedidos:cancelar");
            d.Roles.Add("Gerente");
            d.ExtraClaims["sid"] = "sessao-1";
        });

        var cancel = await SendAsync(app, "/cancelar", token);
        var read = await SendAsync(app, "/ler", token);

        await Assert.That(cancel.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(read.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task MultiTenant_rejection_log_never_contains_the_tenant_claim_value()
    {
        using var testIssuer = new TestTokenIssuer(Issuer, Audience);
        await using var app = await CreateAppAsync(security => security.AddAspNetCore(), testIssuer.SigningKey,
            o => o.MultiTenant = true, MultiTenantConfig);
        const string Injected = "tenant\nINFO acesso liberado para admin";
        const string Unregistered = "bbbbbbbb-0000-0000-0000-00000000dead";

        var malformed = await SendAsync(app, "/tenant", testIssuer.CreateToken(d => { d.ExternalTenantId = Injected; d.ExtraClaims["sid"] = "s"; }));
        var unknown = await SendAsync(app, "/tenant", testIssuer.CreateToken(d => { d.ExternalTenantId = Unregistered; d.ExtraClaims["sid"] = "s"; }));

        await Assert.That(malformed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(unknown.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(app.Logs.All).DoesNotContain("acesso liberado");
        await Assert.That(app.Logs.All).DoesNotContain(Unregistered);
        await Assert.That(app.Logs.All).Contains("tenant do token");
    }

    private static async Task<HttpResponseMessage> SendAsync(TestApp app, string path, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return await app.Client.SendAsync(request);
    }

    private static Task<TestApp> CreateAppAsync(Action<SecurityBuilder> configureSecurity, SecurityKey signingKey,
        Action<OpenIdConnectApiOptions>? configureOptions = null, IDictionary<string, string?>? configuration = null)
    {
        return TestApp.StartAsync(
            builder =>
            {
                builder.Services.AddTecSecurity(builder.Configuration, security =>
                {
                    configureSecurity(security);
                    TEC.Security.OpenIdConnect.OpenIdConnectExtensions.AddOpenIdConnectApiCore(security, "Keycloak", options =>
                    {
                        options.Authority = Issuer;
                        options.Audience = Audience;
                        configureOptions?.Invoke(options);
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

                app.MapGet("/so-pessoas", () => "pessoa").RequireTecAuthorization(kinds: TecPrincipalKinds.User);
                app.MapGet("/so-aplicacoes", () => "aplicacao").RequireTecAuthorization(kinds: TecPrincipalKinds.Application);
                app.MapGet("/tenant", (ISecurityUser user) => user.TenantId ?? "-").RequireTecAuthorization();
                app.MapGet("/cancelar", () => "ok").RequireTecAuthorization(permissions: "pedidos:cancelar");
                app.MapGet("/ler", () => "ok").RequireTecAuthorization(permissions: "pedidos:ler");
            },
            configuration);
    }
}
