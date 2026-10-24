using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.DependencyInjection;
using TEC.Security.Testing;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>Ponta a ponta (TestServer): autenticação, autorização, respostas e regressões de segurança.</summary>
public class HttpSecurityTests
{
    private const string Tid = "11111111-1111-1111-1111-111111111111";

    private static readonly Dictionary<string, string?> BaseConfig = new()
    {
        ["Security:Tenants:contoso:IdentityProviders:Test:0"] = Tid,
        ["Security:Permissions:Roles:Gerente:0"] = "pedidos:cancelar"
    };

    private static async Task<(TestApp App, TestTokenIssuer Issuer, GeneratedApiKey ApiKey)> StartAsync(
        Action<SecurityAspNetCoreOptions>? aspNetCore = null, Action<WebApplication>? extraMap = null, string environment = "Testing",
        Dictionary<string, string?>? config = null)
    {
        var issuer = new TestTokenIssuer();
        var apiKey = ApiKeyGenerator.Generate("erp-contoso");
        var configuration = new Dictionary<string, string?>(BaseConfig)
        {
            ["Security:ApiKeys:Keys:erp-contoso:Hash"] = apiKey.Hash,
            ["Security:ApiKeys:Keys:erp-contoso:TenantId"] = "contoso",
            ["Security:ApiKeys:Keys:erp-contoso:Permissions:0"] = "pedidos:ler",
            ["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = DateTimeOffset.UtcNow.AddDays(1).ToString("O")
        };
        foreach (var (key, value) in config ?? [])
            configuration[key] = value;

        var app = await TestApp.StartAsync(
            builder => builder.Services.AddTecSecurity(builder.Configuration, security => security
                .AddAspNetCore(aspNetCore)
                .AddApiKeys()
                .AddTestJwt(issuer)),
            app =>
            {
                app.MapGet("/publico", () => "ok").AllowAnonymous();
                app.MapGet("/sem-atributo", () => "ok");
                app.MapGet("/eu", (ISecurityUser user, ICurrentUser current, ICurrentTenant tenant) =>
                    $"{user.Kind}|{user.Id}|{tenant.Id}|{current.TenantId}|{string.Join(',', user.Permissions.Order())}");
                app.MapGet("/pedidos", () => "lista").RequireTecAuthorization(permissions: "pedidos:ler");
                app.MapDelete("/pedidos", () => "cancelado").RequireTecAuthorization(permissions: "pedidos:cancelar", kinds: TecPrincipalKinds.User);
                app.MapGet("/escopo", () => "ok").RequireTecAuthorization(scopes: "api.read");
                app.MapGet("/hubs/chat/negotiate", () => "hub").RequireTecAuthorization();
                app.MapGet("/fora-do-hub", () => "ok").RequireTecAuthorization();
                extraMap?.Invoke(app);
            },
            configuration, environment);

        return (app, issuer, apiKey);
    }

    private static HttpRequestMessage Get(string path, string? token = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null)
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    // ---------------------------------------------------------------- fechado por padrão

    [Test]
    public async Task Endpoint_without_attribute_requires_authentication_and_returns_ApiResponse()
    {
        var (app, _, _) = await StartAsync();
        await using var _ = app;

        var response = await app.Client.SendAsync(Get("/sem-atributo"));
        string body = await response.Content.ReadAsStringAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(body).Contains("SEGURANCA_NAO_AUTENTICADO");
        await Assert.That(body).Contains("traceId");
        await Assert.That(response.Headers.WwwAuthenticate.ToString()).Contains("Bearer");
    }

    [Test]
    public async Task AllowAnonymous_stays_public()
    {
        var (app, _, _) = await StartAsync();
        await using var _ = app;

        var response = await app.Client.SendAsync(Get("/publico"));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Valid_token_creates_normalized_user_with_catalog_tenant_and_permissions()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        string token = issuer.CreateToken(t => { t.Subject = "user-1"; t.ExternalTenantId = Tid; t.Roles.Add("Gerente"); });

        string body = await (await app.Client.SendAsync(Get("/eu", token))).Content.ReadAsStringAsync();

        await Assert.That(body).IsEqualTo("User|user-1|contoso|contoso|Gerente,pedidos:cancelar");
    }

    // ---------------------------------------------------------------- 401 x 403

    [Test]
    public async Task Without_permission_is_403_with_audit_and_with_permission_is_200()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        string withoutPermission = issuer.CreateToken(t => t.Subject = "user-2");
        string withPermission = issuer.CreateToken(t => t.Roles.Add("pedidos:ler"));

        var denied = await app.Client.SendAsync(Get("/pedidos", withoutPermission));
        var enabled = await app.Client.SendAsync(Get("/pedidos", withPermission));

        await Assert.That(denied.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(await denied.Content.ReadAsStringAsync()).Contains("SEGURANCA_ACESSO_NEGADO");
        await Assert.That(app.Logs.Entries.Any(e => e.EventId == 3203 && e.Message.Contains("user-2") && e.Message.Contains("permission"))).IsTrue();
        await Assert.That(enabled.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    public async Task Kinds_User_denies_application_token_even_with_permission()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        string appToken = issuer.CreateToken(t => { t.IsApplication = true; t.Roles.Add("pedidos:cancelar"); });

        var response = await app.Client.SendAsync(new HttpRequestMessage(HttpMethod.Delete, "/pedidos")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", appToken) }
        });

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
    }

    [Test]
    public async Task Required_scope_denies_application_token_and_accepts_user_with_scope()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;

        var application = await app.Client.SendAsync(Get("/escopo", issuer.CreateToken(t => { t.IsApplication = true; t.Roles.Add("x"); })));
        var user = await app.Client.SendAsync(Get("/escopo", issuer.CreateToken(t => t.Scopes.Add("api.read"))));

        await Assert.That(application.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(user.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    // ---------------------------------------------------------------- regressões de segurança do token

    [Test]
    public async Task Injected_tec_perm_claim_does_not_grant_permission()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        string token = issuer.CreateToken(t =>
        {
            t.ExtraClaims["tec_perm"] = "pedidos:ler";
            t.ExtraClaims["tec_normalized"] = "1";
            t.ExtraClaims["tec_tenant"] = "contoso";
        });

        var response = await app.Client.SendAsync(Get("/pedidos", token));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
    }

    [Test]
    public async Task Alg_none_token_is_rejected()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        string header = Base64Url("""{"alg":"none","typ":"JWT"}""");
        long exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        string payload = Base64Url($$"""{"iss":"{{issuer.Issuer}}","aud":"{{issuer.Audience}}","sub":"x","roles":["pedidos:ler"],"exp":{{exp}}}""");

        var response = await app.Client.SendAsync(Get("/pedidos", $"{header}.{payload}."));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task HS256_token_signed_with_arbitrary_key_is_rejected()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        string token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer.Issuer,
            Audience = issuer.Audience,
            Claims = new Dictionary<string, object> { ["sub"] = "x", ["roles"] = new[] { "pedidos:ler" } },
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(new byte[32]), SecurityAlgorithms.HmacSha256)
        });

        var response = await app.Client.SendAsync(Get("/pedidos", token));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Token_from_another_key_expired_or_for_another_audience_is_rejected()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        using var other = new TestTokenIssuer(issuer.Issuer, issuer.Audience);

        var otherKey = await app.Client.SendAsync(Get("/sem-atributo", other.CreateToken()));
        var expired = await app.Client.SendAsync(Get("/sem-atributo", issuer.CreateToken(t =>
        {
            t.IssuedAt = DateTimeOffset.UtcNow.AddMinutes(-20);
            t.Lifetime = TimeSpan.FromMinutes(10);
        })));
        var otherAudience = await app.Client.SendAsync(Get("/sem-atributo", issuer.CreateToken(t => t.Audience = "api://outra")));

        await Assert.That(otherKey.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(expired.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(otherAudience.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Unknown_issuer_Basic_and_malformed_token_are_401_not_anonymous()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        using var unknown = new TestTokenIssuer("https://emissor-desconhecido.test/", issuer.Audience);

        var basic = new HttpRequestMessage(HttpMethod.Get, "/sem-atributo") { Headers = { Authorization = new AuthenticationHeaderValue("Basic", "dXNlcjpwYXNz") } };
        var malformed = await app.Client.SendAsync(Get("/sem-atributo", "nao.e.um-jwt"));

        await Assert.That((await app.Client.SendAsync(Get("/sem-atributo", unknown.CreateToken()))).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That((await app.Client.SendAsync(basic)).StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(malformed.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Two_Authorization_headers_are_rejected()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        var request = new HttpRequestMessage(HttpMethod.Get, "/sem-atributo");
        request.Headers.TryAddWithoutValidation("Authorization", ["Bearer " + issuer.CreateToken(), "Bearer " + issuer.CreateToken()]);

        var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Token_above_maximum_length_is_rejected()
    {
        var (app, issuer, _) = await StartAsync(o => o.MaxTokenLength = 2048);
        await using var _ = app;
        string token = issuer.CreateToken(t => t.ExtraClaims["enchimento"] = new string('x', 4000));

        var response = await app.Client.SendAsync(Get("/sem-atributo", token));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Failure_log_does_not_contain_the_token()
    {
        var (app, issuer, _) = await StartAsync();
        await using var _ = app;
        string token = issuer.CreateToken(t => { t.IssuedAt = DateTimeOffset.UtcNow.AddHours(-1); });

        await app.Client.SendAsync(Get("/sem-atributo", token));

        await Assert.That(app.Logs.All).DoesNotContain(token.Split('.')[1]);
        await Assert.That(app.Logs.Entries.Any(e => e.EventId == 3201)).IsTrue();
    }

    // ---------------------------------------------------------------- SignalR

    [Test]
    public async Task Query_token_is_only_accepted_on_configured_hubs()
    {
        var (app, issuer, _) = await StartAsync(o => o.HubPaths.Add("/hubs/chat"));
        await using var _ = app;
        string token = issuer.CreateToken();

        var hub = await app.Client.SendAsync(Get("/hubs/chat/negotiate?access_token=" + token));
        var outside = await app.Client.SendAsync(Get("/fora-do-hub?access_token=" + token));

        await Assert.That(hub.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(outside.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    // ---------------------------------------------------------------- API key

    [Test]
    public async Task Valid_API_key_authenticates_tenant_application()
    {
        var (app, _, apiKey) = await StartAsync();
        await using var _ = app;
        var request = Get("/eu");
        request.Headers.Add("X-Api-Key", apiKey.Key);

        string body = await (await app.Client.SendAsync(request)).Content.ReadAsStringAsync();

        await Assert.That(body).IsEqualTo("Application|apikey:erp-contoso|contoso|contoso|pedidos:ler");
    }

    [Test]
    public async Task API_key_without_HTTPS_or_in_query_string_is_rejected()
    {
        var (app, _, apiKey) = await StartAsync();
        await using var _ = app;
        var http = new HttpRequestMessage(HttpMethod.Get, "http://localhost/pedidos");
        http.Headers.Add("X-Api-Key", apiKey.Key);

        var withoutHttps = await app.Client.SendAsync(http);
        var inQuery = await app.Client.SendAsync(Get("/pedidos?api_key=" + apiKey.Key));

        await Assert.That(withoutHttps.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(inQuery.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    // ---------------------------------------------------------------- inicialização

    [Test]
    public async Task TecAuthorize_with_AllowAnonymous_prevents_startup() =>
        await Assert.That(async () =>
        {
            var (app, _, _) = await StartAsync(extraMap: a =>
                a.MapGet("/conflito", () => "x").AllowAnonymous().WithMetadata(new TecAuthorizeAttribute { Permissions = "x:y" }));
            await app.DisposeAsync();
        }).Throws<InvalidOperationException>();

    [Test]
    public async Task TecAuthorize_with_empty_value_is_rejected_at_mapping()
    {
        await Assert.That(() => new TecAuthorizeAttribute { Roles = " , " }.GetRequirement()).Throws<InvalidOperationException>();
        await Assert.That(() => new TecAuthorizeAttribute { Permissions = "com espaço" }.GetRequirement()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Test_provider_does_not_start_in_production() =>
        await Assert.That(async () =>
        {
            var (app, issuer, _) = await StartAsync(environment: "Production");
            await using var _ = app;
            await app.Client.SendAsync(Get("/sem-atributo", issuer.CreateToken()));
        }).Throws<InvalidOperationException>();

    // ---------------------------------------------------------------- workers

    [Test]
    public async Task RunAs_with_system_identity_applies_only_inside_the_scope()
    {
        var (app, _, _) = await StartAsync();
        await using var _ = app;
        var context = app.Services.GetRequiredService<ISecurityContext>();
        await using var scope = app.Services.CreateAsyncScope();
        var user = scope.ServiceProvider.GetRequiredService<ISecurityUser>();

        var system = await context.CreateSystemPrincipalAsync("fechamento-mensal", "contoso", ["pedidos:cancelar"]);
        PrincipalKind inside;
        string? tenant;
        using (context.RunAs(system.Value))
        {
            inside = user.Kind;
            tenant = user.TenantId;
        }

        await Assert.That(inside).IsEqualTo(PrincipalKind.System);
        await Assert.That(tenant).IsEqualTo("contoso");
        await Assert.That(user.IsAuthenticated).IsFalse();
        await Assert.That(() => context.RunAs(new System.Security.Claims.ClaimsPrincipal())).Throws<InvalidOperationException>();
        await Assert.That((await context.CreateSystemPrincipalAsync("Nome Invalido")).IsFailure).IsTrue();
        await Assert.That((await context.CreateSystemPrincipalAsync("job-x", "tenant-inexistente")).IsFailure).IsTrue();
    }

    private static string Base64Url(string json) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
