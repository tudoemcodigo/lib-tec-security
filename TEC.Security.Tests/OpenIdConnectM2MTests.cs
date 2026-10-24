using System.Net;
using System.Text.Json;
using TEC.Security.Abstractions;
using TEC.Security.OpenIdConnect;
using TEC.Security.Tokens;

namespace TEC.Security.Tests;

public class OpenIdConnectM2MTests
{
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

    private sealed record AccessTokenResponse(string access_token, int expires_in, string token_type = "Bearer");
}
