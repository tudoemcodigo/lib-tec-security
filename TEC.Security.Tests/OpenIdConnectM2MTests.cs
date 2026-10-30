using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tests.Infrastructure;
using TEC.Security.Tokens;
using TEC.Vault.Abstractions;

namespace TEC.Security.Tests;

public class OpenIdConnectM2MTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 29, 12, 0, 0, TimeSpan.Zero);

    [Test]
    public async Task M2M_token_acquisition_obtains_and_caches_bearer_token()
    {
        var fakeHandler = new FakeOAuthTokenHandler(new AccessTokenResponse("token-jwt-m2m-12345", 3600));
        using var httpClient = new HttpClient(fakeHandler);

        var options = new OpenIdConnectClientOptions
        {
            Authority = "https://auth.empresa.com/realms/corp",
            ClientId = "meu-servico",
            ClientSecret = "segredo-super-secreto"
        };

        using var provider = new OpenIdConnectAccessTokenProvider(httpClient, options);

        // 1ª chamada: vai ao endpoint OAuth
        var token1 = await provider.GetTokenAsync(["api.ler"]);
        await Assert.That(token1.Token).IsEqualTo("token-jwt-m2m-12345");
        await Assert.That(fakeHandler.CallsCount).IsEqualTo(1);

        // 2ª chamada: aproveita cache em memória (zero chamadas HTTP adicionais)
        var token2 = await provider.GetTokenAsync(["api.ler"]);
        await Assert.That(token2.Token).IsEqualTo("token-jwt-m2m-12345");
        await Assert.That(fakeHandler.CallsCount).IsEqualTo(1);
    }

    // ---------------------------------------------------------------- expires_in

    [Test]
    [Arguments("\"abc\"")]
    [Arguments("-1")]
    [Arguments("0")]
    [Arguments("3600.5")]
    [Arguments("true")]
    [Arguments("{}")]
    public async Task Invalid_expires_in_fails_closed(string expiresIn)
    {
        using var provider = Provider(new FixedResponseHandler($$"""{"access_token":"t","token_type":"Bearer","expires_in":{{expiresIn}}}"""));

        var thrown = await Assert.That(async () => await provider.GetTokenAsync(["api.ler"])).ThrowsExactly<SecurityTokenAcquisitionException>();

        await Assert.That(thrown!.InnerException?.Message ?? "").Contains("expires_in");
    }

    [Test]
    [Arguments("""{"access_token":"t"}""", 60)]                          // ausente: validade curta e conservadora
    [Arguments("""{"access_token":"t","expires_in":null}""", 60)]
    [Arguments("""{"access_token":"t","expires_in":"3600"}""", 3600)]    // texto numérico (endpoint v1 do Entra ID)
    [Arguments("""{"access_token":"t","expires_in":315360000}""", 86400)] // 10 anos: o cache considera no máximo 24 h
    public async Task Expires_in_defines_a_conservative_lifetime(string body, int expectedSeconds)
    {
        var clock = new ManualTimeProvider(Now);
        using var provider = Provider(new FixedResponseHandler(body), clock);

        var token = await provider.GetTokenAsync(["api.ler"]);

        await Assert.That(token.ExpiresOn).IsEqualTo(Now.AddSeconds(expectedSeconds));
    }

    // ---------------------------------------------------------------- resposta: teto, tempo limite e status

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task Oversized_token_response_is_rejected_without_reading_it_all(bool withContentLength)
    {
        string big = """{"access_token":"t","expires_in":3600,"enchimento":" """ + new string('x', 400_000) + "\"}";
        using var provider = Provider(new FixedResponseHandler(big, chunked: !withContentLength));

        var thrown = await Assert.That(async () => await provider.GetTokenAsync(["api.ler"])).ThrowsExactly<SecurityTokenAcquisitionException>();

        await Assert.That(thrown!.InnerException?.Message ?? "").Contains("tamanho máximo");
    }

    [Test]
    public async Task Token_endpoint_that_stalls_in_the_body_is_cut_by_the_timeout()
    {
        var options = Options();
        options.Timeout = TimeSpan.FromMilliseconds(300);
        using var provider = new OpenIdConnectAccessTokenProvider(new HttpClient(new StallingBodyHandler()), options);
        var watch = Stopwatch.StartNew();

        var thrown = await Assert.That(async () => await provider.GetTokenAsync(["api.ler"])).ThrowsExactly<SecurityTokenAcquisitionException>();

        await Assert.That(watch.Elapsed).IsLessThan(TimeSpan.FromSeconds(10));
        await Assert.That(thrown!.InnerException?.Message ?? "").Contains("Tempo limite");
    }

    [Test]
    [Arguments(HttpStatusCode.Redirect)]
    [Arguments(HttpStatusCode.TemporaryRedirect)]
    [Arguments(HttpStatusCode.BadRequest)]
    public async Task Non_success_status_fails_without_exposing_the_body(HttpStatusCode status)
    {
        var handler = new FixedResponseHandler("""{"error":"invalid_client","detalhe":"segredo-vazado"}""", status: status);
        using var provider = Provider(handler);

        var thrown = await Assert.That(async () => await provider.GetTokenAsync(["api.ler"])).ThrowsExactly<SecurityTokenAcquisitionException>();

        await Assert.That(handler.Calls).IsEqualTo(1);   // um pedido só: o redirecionamento não é seguido
        await Assert.That(thrown!.InnerException?.Message ?? "").Contains(((int)status).ToString(System.Globalization.CultureInfo.InvariantCulture));
        await Assert.That(thrown.ToString()).DoesNotContain("segredo-vazado");
    }

    // ---------------------------------------------------------------- registro: validação na subida e HttpClient endurecido

    [Test]
    [Arguments("sem-client-id")]
    [Arguments("endpoint-http")]
    [Arguments("authority-http")]
    [Arguments("sem-segredo")]
    [Arguments("segredo-sem-cofre")]
    [Arguments("private-key-jwt")]
    [Arguments("timeout-zero")]
    [Arguments("timeout-longo")]
    [Arguments("resiliencia-invalida")]
    public async Task Invalid_client_options_prevent_startup(string scenario)
    {
        await Assert.That(async () =>
        {
            await using var app = await TestApp.StartAsync(
                b => b.Services.AddTecSecurity(b.Configuration, s => s.AddOpenIdConnectClient(o =>
                {
                    o.TokenEndpoint = "https://idp.test/oauth2/token";
                    o.ClientId = "servico";
                    o.ClientSecret = "segredo";
                    Break(o, scenario);
                })),
                a => a.MapGet("/x", () => "ok"));
        }).Throws<OptionsValidationException>();
    }

    private static void Break(OpenIdConnectClientOptions o, string scenario)
    {
        switch (scenario)
        {
            case "sem-client-id": o.ClientId = ""; break;
            case "endpoint-http": o.TokenEndpoint = "http://idp.test/oauth2/token"; break;
            case "authority-http": o.Authority = "http://idp.test/realms/corp"; break;
            case "sem-segredo": o.ClientSecret = null; break;
            case "segredo-sem-cofre": o.ClientSecret = null; o.ClientSecretName = "segredo-m2m"; break;
            case "private-key-jwt": o.AuthType = OpenIdConnectM2MAuthType.PrivateKeyJwt; break;
            case "timeout-zero": o.Timeout = TimeSpan.Zero; break;
            case "timeout-longo": o.Timeout = TimeSpan.FromMinutes(6); break;
            case "resiliencia-invalida": o.Resilience.FailureRatio = 2; break;
        }
    }

    [Test]
    public async Task Valid_client_with_secret_from_vault_starts()
    {
        await using var app = await TestApp.StartAsync(
            b =>
            {
                b.Services.AddSingleton<ISecretReader>(new FakeSecretReader("segredo-do-cofre"));
                b.Services.AddTecSecurity(b.Configuration, s => s.AddOpenIdConnectClient(o =>
                {
                    o.TokenEndpoint = "https://idp.test/oauth2/token";
                    o.ClientId = "servico";
                    o.ClientSecretName = "segredo-m2m";
                }));
            },
            a => a.MapGet("/x", () => "ok"));

        await Assert.That(app.Services.GetRequiredService<IAccessTokenProvider>()).IsTypeOf<OpenIdConnectAccessTokenProvider>();
    }

    [Test]
    public async Task Client_registered_twice_is_refused()
    {
        var services = new ServiceCollection();

        await Assert.That(() => services.AddTecSecurity(new ConfigurationBuilder().Build(), s => s
            .AddOpenIdConnectClient(o => { o.Authority = "https://idp.test"; o.ClientId = "a"; o.ClientSecret = "x"; })
            .AddOpenIdConnectClient(o => { o.Authority = "https://idp.test"; o.ClientId = "b"; o.ClientSecret = "y"; })))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Token_endpoint_HttpClient_does_not_follow_redirects_nor_keep_cookies()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecSecurity(new ConfigurationBuilder().Build(), s => s.AddOpenIdConnectClient(o =>
        {
            o.Authority = "https://idp.test/realms/corp";
            o.ClientId = "servico";
            o.ClientSecret = "segredo";
        }));
        await using var provider = services.BuildServiceProvider();

        HttpMessageHandler handler = provider.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(TEC.Security.OpenIdConnect.OpenIdConnectExtensions.M2MHttpClientName);
        while (handler is DelegatingHandler delegating)
            handler = delegating.InnerHandler!;

        await Assert.That(handler).IsTypeOf<SocketsHttpHandler>();
        var sockets = (SocketsHttpHandler)handler;
        await Assert.That(sockets.AllowAutoRedirect).IsFalse();
        await Assert.That(sockets.UseCookies).IsFalse();
        // O cliente vive no Singleton: as conexões precisam ser recicladas para acompanhar troca de DNS do IdP
        await Assert.That(sockets.PooledConnectionLifetime).IsEqualTo(TimeSpan.FromMinutes(2));
    }

    [Test]
    public async Task Blocked_destination_is_logged_by_the_access_token_handler()
    {
        var logs = new TestLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddTecSecurity(new ConfigurationBuilder().Build(), s => s.AddOpenIdConnectClient(o =>
        {
            o.Authority = "https://idp.test/realms/corp";
            o.ClientId = "servico";
            o.ClientSecret = "segredo";
        }));
        services.AddHttpClient("Estoque").AddOpenIdConnectAccessToken(o =>
        {
            o.Scopes.Add("estoque.consultar");
            o.AllowedHosts.Add("estoque.empresa.com");
        });
        await using var provider = services.BuildServiceProvider();
        using var client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("Estoque");

        await Assert.That(async () => await client.GetAsync(new Uri("https://outro-host.test/dados"))).Throws<HttpRequestException>();
        await Assert.That(logs.Entries.Any(e => e.EventId == 3121)).IsTrue();
    }

    // ---------------------------------------------------------------- apoio

    private static OpenIdConnectClientOptions Options() => new()
    {
        TokenEndpoint = "https://idp.test/oauth2/token",
        ClientId = "servico",
        ClientSecret = "segredo"
    };

    private static OpenIdConnectAccessTokenProvider Provider(HttpMessageHandler handler, TimeProvider? clock = null) =>
        new(new HttpClient(handler), Options(), time: clock);

    private sealed class FakeOAuthTokenHandler(AccessTokenResponse response) : HttpMessageHandler
    {
        public int CallsCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CallsCount++;
            var res = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(response), System.Text.Encoding.UTF8, "application/json")
            };
            return Task.FromResult(res);
        }
    }

    /// <summary>Resposta fixa; <c>chunked</c> = corpo sem Content-Length (stream que não sabe o próprio tamanho).</summary>
    private sealed class FixedResponseHandler(string body, bool chunked = false, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public int Calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            byte[] bytes = Encoding.UTF8.GetBytes(body);
            HttpContent content = chunked
                ? new StreamContent(new UnknownLengthStream(bytes))
                : new ByteArrayContent(bytes);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            var response = new HttpResponseMessage(status) { Content = content };
            if (status is HttpStatusCode.Redirect or HttpStatusCode.TemporaryRedirect)
                response.Headers.Location = new Uri("https://atacante.test/token");
            return Task.FromResult(response);
        }
    }

    /// <summary>Responde os headers na hora e trava no corpo até o cancelamento.</summary>
    private sealed class StallingBodyHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StallingStream()) });
    }

    private sealed class UnknownLengthStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;

        public override long Length => throw new NotSupportedException();
    }

    private sealed class StallingStream : Stream
    {
        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed record AccessTokenResponse(string access_token, int expires_in, string token_type = "Bearer");
}
