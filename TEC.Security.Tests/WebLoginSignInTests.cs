using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TEC.Core.Security;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.Claims;
using TEC.Security.DependencyInjection;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>
/// Login direto por ID token (login por senha do BFF confidencial, ADR SEC 0002): só o token do próprio IdP, para o próprio client,
/// dentro da validade e com identidade aceita pelo normalizador abre a sessão; qualquer outro é recusado sem cookie.
/// </summary>
public class WebLoginSignInTests
{
    private const string Emissor = "https://idp.test/";
    private const string Cliente = "site";

    private static readonly RsaSecurityKey Chave = new(RSA.Create(2048)) { KeyId = "chave-do-idp" };
    private static readonly RsaSecurityKey OutraChave = new(RSA.Create(2048)) { KeyId = "chave-do-idp" };

    private static async Task<TestApp> StartAsync(bool aceitaDireto = true) =>
        await TestApp.StartAsync(
            builder => builder.Services.AddTecSecurity(builder.Configuration, security => security
                .AddAspNetCore()
                .AddWebLoginProvider(new WebLoginDefinition
                {
                    Scheme = "Web",
                    Provider = "Teste",
                    CreateIdentity = (Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext _, out string reason) =>
                    {
                        reason = "não usado";
                        return null;
                    },
                    CreateIdentityFromClaims = aceitaDireto ? DasClaims : null,
                    Configure = (o, _) =>
                    {
                        o.ClientId = Cliente;
                        var configuracao = new OpenIdConnectConfiguration
                        {
                            Issuer = Emissor,
                            AuthorizationEndpoint = "https://idp.test/authorize",
                            TokenEndpoint = "https://idp.test/token",
                        };
                        configuracao.SigningKeys.Add(Chave);
                        o.Configuration = configuracao;
                        o.TokenValidationParameters.ValidIssuer = Emissor;
                    },
                })),
            app =>
            {
                app.MapGet("/pagina", (HttpContext c) => c.User.FindFirst("sub")?.Value ?? c.User.Identity?.Name ?? "ok");
                app.MapPost("/entrar", async (HttpContext c, WebLoginSignIn entrada) =>
                {
                    string token = await new StreamReader(c.Request.Body).ReadToEndAsync();
                    var propriedades = new AuthenticationProperties();
                    propriedades.Items["meu.item"] = "fica";
                    var resultado = await entrada.SignInWithIdTokenAsync(c, token, propriedades, c.RequestAborted);
                    return resultado.IsSuccess ? Results.NoContent() : Results.Unauthorized();
                }).AllowAnonymous();
                app.MapTecWebLogin();
            });

    private static ExternalIdentity? DasClaims(IReadOnlyList<Claim> claims, IServiceProvider services, out string reason)
    {
        var sujeito = claims.FirstOrDefault(c => c.Type is "sub" or ClaimTypes.NameIdentifier)?.Value;
        reason = sujeito is null ? "sem sub" : string.Empty;
        return sujeito is null ? null : new ExternalIdentity { Scheme = "Web", Provider = "Teste", UserId = sujeito, Kind = PrincipalKind.User };
    }

    private static string Token(
        string emissor = Emissor, string audiencia = Cliente, SecurityKey? chave = null, DateTime? expira = null, bool comSujeito = true)
    {
        var claims = new Dictionary<string, object> { ["name"] = "Ana" };
        if (comSujeito)
            claims["sub"] = "ana-1";
        var agora = DateTime.UtcNow;
        var fim = expira ?? agora.AddMinutes(5);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = emissor,
            Audience = audiencia,
            Claims = claims,
            IssuedAt = fim < agora ? fim.AddMinutes(-10) : agora,
            NotBefore = fim < agora ? fim.AddMinutes(-10) : agora,
            Expires = fim,
            SigningCredentials = new SigningCredentials(chave ?? Chave, SecurityAlgorithms.RsaSha256),
        });
    }

    private static async Task<HttpResponseMessage> Entrar(TestApp app, string token) =>
        await app.Client.PostAsync("/entrar", new StringContent(token, Encoding.UTF8, "text/plain"));

    private static string? CookieDeSessao(HttpResponseMessage resposta) =>
        resposta.Headers.TryGetValues("Set-Cookie", out var valores)
            ? valores.FirstOrDefault(v => v.StartsWith(SecurityBuilderWebLoginExtensions.CookieName, StringComparison.Ordinal))
            : null;

    [Test]
    public async Task TokenDoIdp_ParaOProprioCliente_AbreASessao_ComOCookieEndurecido()
    {
        await using var app = await StartAsync();

        var resposta = await Entrar(app, Token());
        var cookie = CookieDeSessao(resposta);
        var pagina = new HttpRequestMessage(HttpMethod.Get, "/pagina");
        pagina.Headers.Accept.ParseAdd("application/json");
        pagina.Headers.Add("Cookie", cookie!.Split(';')[0]);
        var lida = await app.Client.SendAsync(pagina);

        await Assert.That(resposta.StatusCode).IsEqualTo(HttpStatusCode.NoContent);
        await Assert.That(cookie.ToLowerInvariant()).Contains("httponly");
        await Assert.That(cookie.ToLowerInvariant()).Contains("secure");
        await Assert.That(lida.StatusCode).IsEqualTo(HttpStatusCode.OK);
    }

    [Test]
    [Arguments("audiencia")]
    [Arguments("emissor")]
    [Arguments("chave")]
    [Arguments("vencido")]
    [Arguments("sem-sujeito")]
    public async Task TokenQueNaoEDoIdpParaEsteCliente_ERecusado_SemCookie(string caso)
    {
        await using var app = await StartAsync();
        string token = caso switch
        {
            "audiencia" => Token(audiencia: "outro-cliente"),
            "emissor" => Token(emissor: "https://outro-idp.test/"),
            "chave" => Token(chave: OutraChave),
            "vencido" => Token(expira: DateTime.UtcNow.AddHours(-1)),
            _ => Token(comSujeito: false),
        };

        var resposta = await Entrar(app, token);

        await Assert.That(resposta.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(CookieDeSessao(resposta)).IsNull();
    }

    [Test]
    [Arguments("")]
    [Arguments("nao-e-jwt")]
    [Arguments("eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbmEtMSIsImF1ZCI6InNpdGUiLCJpc3MiOiJodHRwczovL2lkcC50ZXN0LyJ9.")]
    public async Task TokenMalFormadoOuSemAssinatura_ERecusado(string token)
    {
        await using var app = await StartAsync();

        var resposta = await Entrar(app, token);

        await Assert.That(resposta.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(CookieDeSessao(resposta)).IsNull();
    }

    [Test]
    public async Task TokenGrandeDemais_ERecusadoSemValidar()
    {
        await using var app = await StartAsync();

        var resposta = await Entrar(app, new string('a', 17 * 1024));

        await Assert.That(resposta.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
    }

    [Test]
    public async Task ProvedorQueNaoAceitaEntradaDireta_Recusa_MesmoComTokenValido()
    {
        await using var app = await StartAsync(aceitaDireto: false);

        var resposta = await Entrar(app, Token());

        await Assert.That(app.Services.GetRequiredService<WebLoginSignIn>().Supported).IsFalse();
        await Assert.That(resposta.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(CookieDeSessao(resposta)).IsNull();
    }
}
