using System.Net;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using TEC.Core.Security;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.Claims;
using TEC.Security.DependencyInjection;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>Login web: Authorization Code + PKCE, 401 para chamadas de API e cookie endurecido (sem rede: metadados estáticos).</summary>
public class WebLoginTests
{
    internal static async Task<TestApp> StartAsync(Action<CookieAuthenticationOptions>? cookie = null) =>
        await TestApp.StartAsync(
            builder => builder.Services.AddTecSecurity(builder.Configuration, security => security
                .AddAspNetCore()
                .AddWebLoginProvider(new WebLoginDefinition
                {
                    Scheme = "Web",
                    Provider = "Teste",
                    CreateIdentity = (Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext _, out string reason) =>
                    {
                        reason = string.Empty;
                        return new ExternalIdentity { Scheme = "Web", Provider = "Teste", UserId = "u1", Kind = PrincipalKind.User };
                    },
                    ConfigureCookie = cookie,
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
                })),
            app =>
            {
                app.MapGet("/pagina", () => "ok");
                app.MapTecWebLogin();
            });

    [Test]
    public async Task Navigation_redirects_to_provider_with_PKCE_and_code()
    {
        await using var app = await StartAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/pagina");
        request.Headers.Accept.ParseAdd("text/html");

        var response = await app.Client.SendAsync(request);
        string location = response.Headers.Location?.ToString() ?? "";

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Redirect);
        await Assert.That(location).StartsWith("https://idp.test/authorize");
        await Assert.That(location).Contains("response_type=code");
        await Assert.That(location).Contains("code_challenge_method=S256");
        await Assert.That(location).Contains("nonce=");
        await Assert.That(location).DoesNotContain("id_token");
    }

    [Test]
    public async Task API_call_gets_401_instead_of_redirect()
    {
        await using var app = await StartAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/pagina");
        request.Headers.Accept.ParseAdd("application/json");

        var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(await response.Content.ReadAsStringAsync()).Contains("SEGURANCA_NAO_AUTENTICADO");
    }

    [Test]
    public async Task Login_with_external_returnUrl_returns_to_root()
    {
        await using var app = await StartAsync();
        var request = new HttpRequestMessage(HttpMethod.Get, "/account/login?returnUrl=https://evil.com/");
        request.Headers.Accept.ParseAdd("text/html");

        var response = await app.Client.SendAsync(request);
        var cookies = response.Headers.TryGetValues("Set-Cookie", out var values) ? string.Join(";", values) : "";

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Redirect);
        await Assert.That(cookies.ToLowerInvariant()).Contains("secure");
        await Assert.That(cookies.ToLowerInvariant()).Contains("httponly");
    }

    [Test]
    public async Task Cookie_is_hardened()
    {
        await using var app = await StartAsync();
        var cookie = app.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get("Web");

        await Assert.That(cookie.Cookie.Name).IsEqualTo("__Host-TEC.Auth");
        await Assert.That(cookie.Cookie.HttpOnly).IsTrue();
        await Assert.That(cookie.Cookie.SecurePolicy).IsEqualTo(CookieSecurePolicy.Always);
        await Assert.That(cookie.Cookie.SameSite).IsEqualTo(SameSiteMode.Lax);
    }

    [Test]
    public async Task Cookie_without_Secure_or_with_SameSite_None_prevents_startup() =>
        await Assert.That(async () =>
        {
            await using var app = await StartAsync(c => c.Cookie.SameSite = SameSiteMode.None);
        }).Throws<OptionsValidationException>();
}
