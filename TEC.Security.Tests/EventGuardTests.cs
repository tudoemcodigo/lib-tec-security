using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using TEC.Core.Security;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.Claims;
using TEC.Security.DependencyInjection;
using TEC.Security.Testing;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>
/// Delegates de evento continuam rodando, mas não aprovam sozinhos (falha fechada): <c>Success()</c> ou principal definido antes
/// da validação/normalização, troca do token ou do principal validados e gravação de identidade forjada no cookie são recusados.
/// </summary>
public class EventGuardTests
{
    // ================================================================ JWT Bearer (ponta a ponta)

    private static Task<TestApp> StartJwtAsync(TestTokenIssuer issuer, Action<JwtBearerEvents> events) =>
        TestApp.StartAsync(
            b =>
            {
                b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer));
                b.Services.PostConfigure<JwtBearerOptions>("Test", o => events(o.Events));
            },
            a => a.MapGet("/admin", () => "ok").RequireTecAuthorization(permissions: "admin:tudo"));

    /// <summary>Identidade legítima (criada pela fábrica) com a permissão de administrador.</summary>
    private static async Task<ClaimsPrincipal> AdminAsync(HttpContext http, string scheme = "Test", string provider = "Test") =>
        (await http.RequestServices.GetRequiredService<SecurityIdentityFactory>().CreateAsync(new ExternalIdentity
        {
            Scheme = scheme, Provider = provider, UserId = "admin", Kind = PrincipalKind.User, Permissions = ["admin:tudo"]
        })).Value;

    private static HttpRequestMessage Bearer(string path, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(path, UriKind.Relative));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task OnMessageReceived_delegate_cannot_approve_before_the_token_is_validated(bool callSuccess)
    {
        using var issuer = new TestTokenIssuer();
        using var attacker = new TestTokenIssuer(issuer.Issuer, issuer.Audience);   // mesmo emissor, outra chave
        await using var app = await StartJwtAsync(issuer, e => e.OnMessageReceived = async context =>
        {
            context.Principal = await AdminAsync(context.HttpContext);
            if (callSuccess)
                context.Success();
        });

        var response = await app.Client.SendAsync(Bearer("/admin", attacker.CreateToken()));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(app.Logs.All).Contains("OnMessageReceived");
    }

    [Test]
    public async Task OnAuthenticationFailed_delegate_cannot_turn_a_rejected_token_into_success()
    {
        using var issuer = new TestTokenIssuer();
        using var attacker = new TestTokenIssuer(issuer.Issuer, issuer.Audience);
        await using var app = await StartJwtAsync(issuer, e => e.OnAuthenticationFailed = async context =>
        {
            context.Principal = await AdminAsync(context.HttpContext);
            context.Success();
        });

        var response = await app.Client.SendAsync(Bearer("/admin", attacker.CreateToken()));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(app.Logs.All).Contains("OnAuthenticationFailed");
    }

    [Test]
    public async Task OnTokenValidated_delegate_cannot_swap_the_validated_token()
    {
        using var issuer = new TestTokenIssuer();
        long exp = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
        // Token sem assinatura, de outro usuário e com o papel que vira permissão de administrador
        string forged = Base64Url("""{"alg":"none","typ":"JWT"}""") + "." + Base64Url(
            $$"""{"iss":"{{issuer.Issuer}}","aud":"{{issuer.Audience}}","sub":"admin","roles":["admin:tudo"],"exp":{{exp}}}""") + ".";
        await using var app = await StartJwtAsync(issuer, e => e.OnTokenValidated = context =>
        {
            context.SecurityToken = new JsonWebToken(forged);
            return Task.CompletedTask;
        });

        var response = await app.Client.SendAsync(Bearer("/admin", issuer.CreateToken(t => t.Subject = "usuario-comum")));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task OnTokenValidated_delegate_cannot_swap_the_validated_principal()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartJwtAsync(issuer, e => e.OnTokenValidated = async context =>
            context.Principal = await AdminAsync(context.HttpContext));

        var response = await app.Client.SendAsync(Bearer("/admin", issuer.CreateToken(t => t.Subject = "usuario-comum")));

        // 401 (recusa na autenticação), não 403 (usuário comum) nem 200 (administrador)
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task Harmless_delegates_still_run_and_a_valid_token_is_accepted()
    {
        using var issuer = new TestTokenIssuer();
        int calls = 0;
        await using var app = await StartJwtAsync(issuer, e =>
        {
            e.OnMessageReceived = _ =>
            {
                Interlocked.Increment(ref calls);
                return Task.CompletedTask;
            };
            e.OnTokenValidated = _ =>
            {
                Interlocked.Increment(ref calls);
                return Task.CompletedTask;
            };
        });

        var response = await app.Client.SendAsync(Bearer("/admin", issuer.CreateToken(t => t.Roles.Add("admin:tudo"))));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(calls).IsEqualTo(2);
    }

    // ================================================================ Login web: OIDC

    private static WebLoginDefinition WebDefinition() => new()
    {
        Scheme = "Web",
        Provider = "Teste",
        CreateIdentity = (Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext _, out string reason) =>
        {
            reason = string.Empty;
            return new ExternalIdentity { Scheme = "Web", Provider = "Teste", UserId = "u1", Kind = PrincipalKind.User };
        },
        Configure = (o, _) =>
        {
            o.ClientId = "site";
            o.Configuration = new OpenIdConnectConfiguration
            {
                Issuer = "https://idp.test/",
                AuthorizationEndpoint = "https://idp.test/authorize",
                TokenEndpoint = "https://idp.test/token"
            };
            o.TokenValidationParameters.ValidIssuer = "https://idp.test/";
        }
    };

    private static Task<TestApp> StartWebAsync(Action<OpenIdConnectOptions>? oidc = null) =>
        TestApp.StartAsync(
            b =>
            {
                b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddWebLoginProvider(WebDefinition()));
                if (oidc is not null)
                    b.Services.PostConfigure("Web.oidc", oidc);
            },
            a =>
            {
                a.MapGet("/pagina", () => "ok");
                a.MapTecWebLogin();
            });

    private static readonly AuthenticationScheme OidcScheme = new("Web.oidc", null, typeof(OpenIdConnectHandler));

    [Test]
    public async Task OIDC_OnMessageReceived_delegate_cannot_create_a_session()
    {
        await using var app = await StartWebAsync(o => o.Events.OnMessageReceived = async context =>
        {
            context.Principal = await AdminAsync(context.HttpContext, "Web", "Teste");
            context.Success();
        });

        // Callback forjado, sem passar pelo provedor: state e code inventados
        var response = await app.Client.PostAsync(new Uri("/signin-oidc", UriKind.Relative), new FormUrlEncodedContent(
            new Dictionary<string, string> { ["state"] = "estado-forjado", ["code"] = "codigo-forjado" }));
        string cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? string.Join(";", values) : "";

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(cookies).DoesNotContain(SecurityBuilderWebLoginExtensions.CookieName);
        await Assert.That(app.Logs.All).Contains("OnMessageReceived");
    }

    [Test]
    [Arguments("authorization-code")]
    [Arguments("token-response")]
    [Arguments("authentication-failed")]
    public async Task OIDC_delegates_cannot_approve_before_normalization(string stage)
    {
        await using var app = await StartWebAsync();
        var options = app.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Web.oidc");
        var http = new DefaultHttpContext { RequestServices = app.Services };
        var forged = await AdminAsync(http, "Web", "Teste");
        HandleRequestResult? result;

        switch (stage)
        {
            case "authorization-code":
                options.Events.OnAuthorizationCodeReceived = c =>
                {
                    c.Principal = forged;
                    c.Success();
                    return Task.CompletedTask;
                };
                var code = new AuthorizationCodeReceivedContext(http, OidcScheme, options, new AuthenticationProperties());
                await options.Events.AuthorizationCodeReceived(code);
                result = code.Result;
                break;

            case "token-response":
                options.Events.OnTokenResponseReceived = c =>
                {
                    c.Principal = forged;
                    c.Success();
                    return Task.CompletedTask;
                };
                var tokenResponse = new TokenResponseReceivedContext(http, OidcScheme, options, new ClaimsPrincipal(), new AuthenticationProperties());
                await options.Events.TokenResponseReceived(tokenResponse);
                result = tokenResponse.Result;
                break;

            default:
                options.Events.OnAuthenticationFailed = c =>
                {
                    c.Principal = forged;
                    c.Success();
                    return Task.CompletedTask;
                };
                var failed = new Microsoft.AspNetCore.Authentication.OpenIdConnect.AuthenticationFailedContext(http, OidcScheme, options)
                {
                    Exception = new InvalidOperationException("falha na troca do código")
                };
                await options.Events.AuthenticationFailed(failed);
                result = failed.Result;
                break;
        }

        await Assert.That(result).IsNotNull();
        await Assert.That(result!.Succeeded).IsFalse();
        await Assert.That(result.Failure).IsNotNull();
    }

    [Test]
    public async Task OIDC_OnTokenValidated_delegate_cannot_swap_the_validated_principal()
    {
        await using var app = await StartWebAsync();
        var options = app.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Web.oidc");
        var http = new DefaultHttpContext { RequestServices = app.Services };
        options.Events.OnTokenValidated = c =>
        {
            c.Principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "admin")], "oidc"));
            return Task.CompletedTask;
        };
        var context = new Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext(http, OidcScheme, options,
            new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "u1")], "oidc")), new AuthenticationProperties());

        await options.Events.TokenValidated(context);

        await Assert.That(context.Result?.Failure).IsNotNull();
    }

    [Test]
    public async Task OIDC_OnTicketReceived_delegate_cannot_swap_the_normalized_identity()
    {
        await using var app = await StartWebAsync();
        var options = app.Services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Web.oidc");
        var http = new DefaultHttpContext { RequestServices = app.Services };
        var factory = app.Services.GetRequiredService<SecurityIdentityFactory>();
        var normalized = (await factory.CreateAsync(new ExternalIdentity { Scheme = "Web", Provider = "Teste", UserId = "u1", Kind = PrincipalKind.User })).Value;
        var other = await AdminAsync(http, "Web", "Teste");

        var untouched = new TicketReceivedContext(http, OidcScheme, options, new AuthenticationTicket(normalized, "Web.oidc"));
        await options.Events.TicketReceived(untouched);

        options.Events.OnTicketReceived = c =>
        {
            c.Principal = other;
            return Task.CompletedTask;
        };
        var swapped = new TicketReceivedContext(http, OidcScheme, options, new AuthenticationTicket(normalized, "Web.oidc"));
        await options.Events.TicketReceived(swapped);

        await Assert.That(untouched.Result).IsNull();
        await Assert.That(swapped.Result is { Handled: true }).IsTrue();
        await Assert.That(http.Response.StatusCode).IsEqualTo(StatusCodes.Status401Unauthorized);
    }

    // ================================================================ Login web: cookie

    private static readonly AuthenticationScheme CookieScheme = new("Web", null, typeof(CookieAuthenticationHandler));

    private static async Task<(ServiceProvider Services, RecordingAuthenticationService Auth, ClaimsPrincipal Principal)> CookieServicesAsync()
    {
        var auth = new RecordingAuthenticationService();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecSecurity(new ConfigurationBuilder().Build());
        services.AddSingleton<IAuthenticationService>(auth);
        var provider = services.BuildServiceProvider();
        var principal = (await provider.GetRequiredService<SecurityIdentityFactory>().CreateAsync(new ExternalIdentity
        {
            Scheme = "Web", Provider = "Teste", UserId = "u1", Kind = PrincipalKind.User
        })).Value;
        return (provider, auth, principal);
    }

    private static AuthenticationProperties SessionProperties()
    {
        string now = DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);
        var properties = new AuthenticationProperties();
        properties.Items[SecurityBuilderWebLoginExtensions.SignedInAtKey] = now;
        properties.Items[SecurityBuilderWebLoginExtensions.ValidatedAtKey] = now;
        return properties;
    }

    [Test]
    public async Task Cookie_round_trip_restores_the_normalized_identity()
    {
        var (services, auth, principal) = await CookieServicesAsync();
        await using var container = services;
        // Ida e volta pelo formato do cookie: o TicketSerializer recria um ClaimsIdentity comum
        var serializer = TicketSerializer.Default;
        var roundTrip = serializer.Deserialize(serializer.Serialize(new AuthenticationTicket(principal, SessionProperties(), "Web")))!;
        bool authenticatedBeforeRestore = new SecurityUser(roundTrip.Principal).IsAuthenticated;
        var context = new CookieValidatePrincipalContext(new DefaultHttpContext { RequestServices = services }, CookieScheme,
            new CookieAuthenticationOptions(), roundTrip);

        await new TecCookieEvents(WebDefinition()).ValidatePrincipal(context);
        var user = new SecurityUser(context.Principal);

        await Assert.That(authenticatedBeforeRestore).IsFalse();   // a marca tec_normalized sozinha não vale
        await Assert.That(user.IsAuthenticated).IsTrue();
        await Assert.That(user.Id).IsEqualTo("u1");
        await Assert.That(auth.SignOuts).IsEqualTo(0);
    }

    [Test]
    public async Task Cookie_delegate_replacing_the_principal_with_a_forged_one_ends_the_session()
    {
        var (services, auth, principal) = await CookieServicesAsync();
        await using var container = services;
        var events = new TecCookieEvents(WebDefinition())
        {
            OnValidatePrincipal = c =>
            {
                c.ReplacePrincipal(NormalizedIdentityTests.Forged());
                return Task.CompletedTask;
            }
        };
        var context = new CookieValidatePrincipalContext(new DefaultHttpContext { RequestServices = services }, CookieScheme,
            new CookieAuthenticationOptions(), new AuthenticationTicket(principal, SessionProperties(), "Web"));

        await events.ValidatePrincipal(context);

        await Assert.That(context.Principal).IsNull();
        await Assert.That(auth.SignOuts).IsEqualTo(1);
    }

    [Test]
    public async Task Cookie_accepts_only_the_normalized_user_identity_at_sign_in()
    {
        var (services, _, principal) = await CookieServicesAsync();
        await using var container = services;
        var events = new TecCookieEvents(WebDefinition());
        var http = new DefaultHttpContext { RequestServices = services };
        var application = (await services.GetRequiredService<SecurityIdentityFactory>().CreateAsync(new ExternalIdentity
        {
            Scheme = "Web", Provider = "Teste", UserId = "servico", Kind = PrincipalKind.Application
        })).Value;

        await Assert.That(async () => await events.SigningIn(SigningIn(http, NormalizedIdentityTests.Forged())))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await events.SigningIn(SigningIn(http, application))).Throws<InvalidOperationException>();
        await events.SigningIn(SigningIn(http, principal));   // identidade normalizada de usuário: aceita
    }

    private static CookieSigningInContext SigningIn(HttpContext http, ClaimsPrincipal principal) =>
        new(http, CookieScheme, new CookieAuthenticationOptions(), principal, new AuthenticationProperties(), new CookieOptions());

    private static string Base64Url(string json) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private sealed class RecordingAuthenticationService : IAuthenticationService
    {
        public int SignOuts;

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            Interlocked.Increment(ref SignOuts);
            return Task.CompletedTask;
        }
    }
}
