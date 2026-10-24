using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using TEC.Vault.Abstractions;
using TEC.Vault.Keys;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tokens;

namespace TEC.Security.Tests;

/// <summary>Tokens entre serviços (handler, cache) e credenciais do Entra ID (client assertion assinada no cofre).</summary>
public class TokenAndCredentialTests
{
    private sealed class RecordingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Last { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Last = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private static (HttpClient Client, RecordingHandler Inner, CountingTokenProvider Provider, ManualTimeProvider Time) CreateClient(
        Action<AccessTokenHandlerOptions>? configure = null)
    {
        var time = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var provider = new CountingTokenProvider(time, TimeSpan.FromHours(1));
        var options = new AccessTokenHandlerOptions { Scopes = { "api://estoque/.default" }, AllowedHosts = { "estoque.contoso.com" } };
        configure?.Invoke(options);
        var inner = new RecordingHandler();
        return (new HttpClient(new AccessTokenHandler(provider, options) { InnerHandler = inner }), inner, provider, time);
    }

    [Test]
    public async Task Token_is_attached_only_for_allowed_host_over_HTTPS()
    {
        var (client, inner, _, _) = CreateClient();

        await client.GetAsync("https://estoque.contoso.com/itens");
        string? header = inner.Last?.Headers.Authorization?.ToString();

        await Assert.That(header).IsEqualTo("Bearer token-1");
        await Assert.That(async () => await client.GetAsync("https://evil.com/")).Throws<HttpRequestException>();
        await Assert.That(async () => await client.GetAsync("http://estoque.contoso.com/")).Throws<HttpRequestException>();
        await Assert.That(async () => await client.GetAsync("https://usuario:senha@estoque.contoso.com/")).Throws<HttpRequestException>();
        await Assert.That(async () => await client.GetAsync("https://estoque.contoso.com.evil.com/")).Throws<HttpRequestException>();
    }

    [Test]
    public async Task Existing_Authorization_is_not_overwritten()
    {
        var (client, inner, provider, _) = CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://estoque.contoso.com/") { Headers = { Authorization = new("Bearer", "do-chamador") } };

        await client.SendAsync(request);

        await Assert.That(inner.Last!.Headers.Authorization!.Parameter).IsEqualTo("do-chamador");
        await Assert.That(provider.Calls).IsEqualTo(0);
    }

    [Test]
    public async Task Options_without_scope_or_host_are_rejected()
    {
        await Assert.That(() => new AccessTokenHandlerOptions { AllowedHosts = { "a.com" } }.Validate()).Throws<InvalidOperationException>();
        await Assert.That(() => new AccessTokenHandlerOptions { Scopes = { "x/.default" } }.Validate()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Cache_reuses_token_and_renews_5_minutes_before_expiry()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var provider = new CountingTokenProvider(time, TimeSpan.FromHours(1));
        string[] scopes = ["api://estoque/.default"];

        var first = await provider.GetTokenAsync(scopes, default);
        var cached = await provider.GetTokenAsync(scopes, default);
        time.Now = time.Now.AddMinutes(56);
        var renewed = await provider.GetTokenAsync(scopes, default);

        await Assert.That(cached.Token).IsEqualTo(first.Token);
        await Assert.That(renewed.Token).IsNotEqualTo(first.Token);
        await Assert.That(provider.Calls).IsEqualTo(2);
        await Assert.That(first.ToString()).DoesNotContain(first.Token);
    }

    [Test]
    public async Task Concurrent_calls_acquire_a_single_token()
    {
        var time = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var provider = new CountingTokenProvider(time, TimeSpan.FromHours(1));

        await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => provider.GetTokenAsync(["x/.default"], default).AsTask()));

        await Assert.That(provider.Calls).IsEqualTo(1);
    }

    // ---------------------------------------------------------------- login web

    [Test]
    [Arguments("/pedidos?id=1", "/pedidos?id=1")]
    [Arguments("https://evil.com", "/")]
    [Arguments("//evil.com", "/")]
    [Arguments("/\\evil.com", "/")]
    [Arguments("javascript:alert(1)", "/")]
    [Arguments("/a\nb", "/")]
    [Arguments(null, "/")]
    public async Task ReturnUrl_only_accepts_local_path(string? returnUrl, string expected) =>
        await Assert.That(WebLoginEndpoints.SafeReturnUrl(returnUrl)).IsEqualTo(expected);

    private static byte[] FromBase64Url(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(padded);
    }
}
