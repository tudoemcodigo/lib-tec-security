using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.Permissions;
using TEC.Security.Testing;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>Regressões dos achados da revisão de segurança.</summary>
public class ReviewRegressionTests
{
    private static Task<TestApp> StartAsync(TestTokenIssuer issuer, Action<WebApplicationBuilder>? extra = null) =>
        TestApp.StartAsync(
            builder =>
            {
                builder.Services.AddTecSecurity(builder.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer));
                extra?.Invoke(builder);
            },
            app =>
            {
                app.MapGet("/x", () => "ok");
                app.MapTecWebLogin();
            });

    // ---------------------------------------------------------------- [TecAuthorize] fora do middleware

    [Test]
    public async Task TecAuthorize_applies_through_IAuthorizeData_as_in_SignalR_hubs_and_Blazor()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartAsync(issuer);
        var provider = app.Services.GetRequiredService<IAuthorizationPolicyProvider>();
        var authorization = app.Services.GetRequiredService<IAuthorizationService>();
        var factory = app.Services.GetRequiredService<Claims.SecurityIdentityFactory>();

        // Mesmo caminho do HubDispatcher do SignalR e do AuthorizeRouteView: só IAuthorizeData
        var policy = await AuthorizationPolicy.CombineAsync(provider, [new TecAuthorizeAttribute { Permissions = "admin:excluir" }]);
        var withoutPermission = (await factory.CreateAsync(new Claims.ExternalIdentity
            { Scheme = "Test", Provider = "Test", UserId = "u1", Kind = PrincipalKind.User })).Value;
        var withPermission = (await factory.CreateAsync(new Claims.ExternalIdentity
            { Scheme = "Test", Provider = "Test", UserId = "u2", Kind = PrincipalKind.User, Roles = ["admin:excluir"] })).Value;

        await Assert.That((await authorization.AuthorizeAsync(withoutPermission, null, policy!)).Succeeded).IsFalse();
        await Assert.That((await authorization.AuthorizeAsync(withPermission, null, policy!)).Succeeded).IsTrue();
        await Assert.That((await authorization.AuthorizeAsync(new System.Security.Claims.ClaimsPrincipal(), null, policy!)).Succeeded).IsFalse();
    }

    [Test]
    public async Task Malformed_TEC_policy_name_fails_closed()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartAsync(issuer);
        var provider = app.Services.GetRequiredService<IAuthorizationPolicyProvider>();

        await Assert.That(async () => await provider.GetPolicyAsync("TEC|p=a b|r=|s=|h=|k=3")).Throws<InvalidOperationException>();
    }

    // ---------------------------------------------------------------- configuração tardia

    [Test]
    public async Task PostConfigure_disabling_audience_prevents_startup()
    {
        using var issuer = new TestTokenIssuer();

        await Assert.That(async () =>
        {
            // Configuração insegura proposital: o teste prova que a aplicação se recusa a subir com ela
#pragma warning disable CA5404
            await using var app = await StartAsync(issuer, b =>
                b.Services.PostConfigure<JwtBearerOptions>("Test", o => o.TokenValidationParameters.ValidateAudience = false));
#pragma warning restore CA5404
        }).Throws<Microsoft.Extensions.Options.OptionsValidationException>();
    }

    [Test]
    public async Task Replacing_the_events_prevents_startup()
    {
        using var issuer = new TestTokenIssuer();

        await Assert.That(async () =>
        {
            await using var app = await StartAsync(issuer, b =>
                b.Services.PostConfigure<JwtBearerOptions>("Test", o => o.Events = new JwtBearerEvents()));
        }).Throws<Microsoft.Extensions.Options.OptionsValidationException>();
    }

    [Test]
    public async Task OnTokenValidated_delegate_approving_alone_does_not_skip_normalization()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartAsync(issuer, b =>
            b.Services.PostConfigure<JwtBearerOptions>("Test", o => o.Events.OnTokenValidated = context =>
            {
                context.Success();
                return Task.CompletedTask;
            }));
        var request = new HttpRequestMessage(HttpMethod.Get, "/x")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", issuer.CreateToken(t => t.ExtraClaims["tec_normalized"] = "1")) }
        };

        var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    // ---------------------------------------------------------------- logout

    [Test]
    [Arguments("cross-site", null, HttpStatusCode.Forbidden)]
    [Arguments(null, "https://evil.com", HttpStatusCode.Forbidden)]
    [Arguments(null, null, HttpStatusCode.Forbidden)]
    public async Task Logout_from_another_site_is_rejected(string? fetchSite, string? origin, HttpStatusCode expected)
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartAsync(issuer);
        var request = new HttpRequestMessage(HttpMethod.Post, "/account/logout");
        if (fetchSite is not null)
            request.Headers.Add("Sec-Fetch-Site", fetchSite);
        if (origin is not null)
            request.Headers.Add("Origin", origin);

        var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(expected);
    }

    [Test]
    public async Task Logout_from_own_site_is_accepted_by_origin()
    {
        var request = new Microsoft.AspNetCore.Http.DefaultHttpContext().Request;
        request.Scheme = "https";
        request.Host = new Microsoft.AspNetCore.Http.HostString("app.contoso.com");
        request.Headers.Origin = "https://app.contoso.com";

        await Assert.That(WebLoginEndpoints.IsSameOrigin(request)).IsTrue();
    }

    // ---------------------------------------------------------------- permissões por tenant

    [Test]
    public async Task Per_tenant_mapping_applies_only_to_that_tenant()
    {
        var options = new PermissionOptions();
        options.Roles["Leitor"] = ["pedidos:ler"];
        options.Tenants["minha-empresa"] = new TenantPermissionOptions { Roles = { ["Admin"] = ["plataforma:admin"] } };
        var store = new ConfigurationPermissionStore(new TestOptionsMonitor<PermissionOptions>(options));

        var home = await store.GetPermissionsAsync(new PermissionContext("EntraId", "Api", "u1", "minha-empresa", PrincipalKind.User, ["Admin", "Leitor"]), default);
        var customer = await store.GetPermissionsAsync(new PermissionContext("EntraId", "Api", "u2", "cliente-x", PrincipalKind.User, ["Admin", "Leitor"]), default);

        await Assert.That(home.Contains("plataforma:admin")).IsTrue();
        await Assert.That(customer.Contains("plataforma:admin")).IsFalse();
        await Assert.That(customer.Contains("pedidos:ler")).IsTrue();
    }
}

/// <summary>Regressões do code review.</summary>
public class CodeReviewRegressionTests
{
    [Test]
    public async Task Parallel_RunAs_in_same_scope_does_not_mix_identities()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await TestApp.StartAsync(
            b => b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer)),
            a => a.MapGet("/x", () => "ok"));
        var context = app.Services.GetRequiredService<ISecurityContext>();
        await using var scope = app.Services.CreateAsyncScope();
        var user = scope.ServiceProvider.GetRequiredService<ISecurityUser>();
        var principals = new List<System.Security.Claims.ClaimsPrincipal>();
        for (int i = 0; i < 8; i++)
            principals.Add((await context.CreateSystemPrincipalAsync($"job-{i}")).Value);

        int errors = 0;
        await Parallel.ForEachAsync(Enumerable.Range(0, 400), async (n, _) =>
        {
            int i = n % principals.Count;
            using (context.RunAs(principals[i]))
            {
                for (int k = 0; k < 50; k++)
                {
                    if (user.Id != $"system:job-{i}")
                        Interlocked.Increment(ref errors);
                    await Task.Yield();
                }
            }
        });

        await Assert.That(errors).IsEqualTo(0);
    }

    [Test]
    public async Task API_call_without_session_does_not_write_OIDC_cookies()
    {
        await using var app = await WebLoginTests.StartAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/pagina");
        request.Headers.Accept.ParseAdd("application/json");

        var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(response.Headers.Contains("Set-Cookie")).IsFalse();
    }

    [Test]
    public async Task API_key_header_change_applies_without_restart()
    {
        using var issuer = new TestTokenIssuer();
        var key = TEC.Security.ApiKeys.ApiKeyGenerator.Generate("erp-teste");
        await using var app = await TestApp.StartAsync(
            b => b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddApiKeys().AddTestJwt(issuer)),
            a => a.MapGet("/x", (ISecurityUser u) => u.Id ?? "-"),
            new Dictionary<string, string?>
            {
                ["Security:ApiKeys:Keys:erp-teste:Hash"] = key.Hash,
                ["Security:ApiKeys:Keys:erp-teste:ExpiresOn"] = DateTimeOffset.UtcNow.AddDays(1).ToString("O")
            });

        app.App.Configuration["Security:ApiKeys:HeaderName"] = "X-Chave";
        ((Microsoft.Extensions.Configuration.IConfigurationRoot)app.App.Configuration).Reload();
        var request = new HttpRequestMessage(HttpMethod.Get, "/x");
        request.Headers.Add("X-Chave", key.Key);
        var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(await response.Content.ReadAsStringAsync()).IsEqualTo("apikey:erp-teste");
    }

    [Test]
    public async Task HTTP_metadata_prevents_startup()
    {
        using var issuer = new TestTokenIssuer();

        await Assert.That(async () =>
        {
            await using var app = await TestApp.StartAsync(
                b =>
                {
                    b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer));
                    b.Services.PostConfigure<JwtBearerOptions>("Test", o => o.RequireHttpsMetadata = false);
                },
                a => a.MapGet("/x", () => "ok"));
        }).Throws<Microsoft.Extensions.Options.OptionsValidationException>();
    }
}
