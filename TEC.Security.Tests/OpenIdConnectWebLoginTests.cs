using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using TEC.Security.AspNetCore;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect;
using TEC.Security.Tests.Fakes;
using TEC.Vault.Abstractions;

namespace TEC.Security.Tests;

/// <summary>
/// Login web do provedor OpenID Connect: o client secret do cofre é conferido na subida e lido de novo a cada login (troca do
/// código e PAR), sem ficar nas opções, então a rotação no cofre vale sem reiniciar.
/// </summary>
public class OpenIdConnectWebLoginTests
{
    private static readonly AuthenticationScheme Scheme = new("Web.oidc", null, typeof(OpenIdConnectHandler));

    private static ServiceProvider Services(FakeSecretReader vault)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISecretReader>(vault);
        services.AddTecSecurity(new ConfigurationBuilder().Build(), s => s
            .AddAspNetCore()
            .AddOpenIdConnectWebLogin("Web", o =>
            {
                o.Authority = "https://idp.test/realms/corp";
                o.ClientId = "portal-web";
                o.ClientSecretName = "portal-web-secret";
            }));
        return services.BuildServiceProvider();
    }

    [Test]
    public async Task Vault_secret_is_read_on_each_code_redemption_and_follows_rotation()
    {
        var vault = new FakeSecretReader("segredo-v1");
        await using var services = Services(vault);
        var options = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Web.oidc");
        var http = new DefaultHttpContext { RequestServices = services };

        var first = new AuthorizationCodeReceivedContext(http, Scheme, options, new AuthenticationProperties()) { TokenEndpointRequest = new OpenIdConnectMessage() };
        await options.Events.AuthorizationCodeReceived(first);
        vault.Value = "segredo-v2";   // rotação no cofre, sem reiniciar
        var second = new AuthorizationCodeReceivedContext(http, Scheme, options, new AuthenticationProperties()) { TokenEndpointRequest = new OpenIdConnectMessage() };
        await options.Events.AuthorizationCodeReceived(second);

        await Assert.That(options.ClientSecret).IsNull();   // o valor não fica guardado nas opções
        await Assert.That(first.TokenEndpointRequest!.ClientSecret).IsEqualTo("segredo-v1");
        await Assert.That(second.TokenEndpointRequest!.ClientSecret).IsEqualTo("segredo-v2");
        await Assert.That(first.Result).IsNull();
        await Assert.That(vault.Reads).IsEqualTo(3);   // subida + duas trocas de código
    }

    [Test]
    public async Task Vault_secret_is_sent_in_pushed_authorization_requests()
    {
        var vault = new FakeSecretReader("segredo-v1");
        await using var services = Services(vault);
        var options = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Web.oidc");
        vault.Value = "segredo-v2";
        var context = new PushedAuthorizationContext(new DefaultHttpContext { RequestServices = services }, Scheme, options,
            new OpenIdConnectMessage(), new AuthenticationProperties());

        await options.Events.PushAuthorization(context);

        await Assert.That(context.ProtocolMessage.ClientSecret).IsEqualTo("segredo-v2");
        await Assert.That(context.HandledClientAuthentication).IsTrue();
    }

    [Test]
    public async Task Missing_vault_secret_prevents_startup_and_vault_failure_fails_the_login()
    {
        // Segredo inexistente: a criação das opções (feita na subida pelo SecuritySchemesStartupValidator) falha
        await using (var missing = Services(new FakeSecretReader(null)))
        {
            await Assert.That(() => missing.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Web.oidc"))
                .Throws<InvalidOperationException>();
        }

        var vault = new FakeSecretReader("segredo-v1");
        await using var services = Services(vault);
        var options = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get("Web.oidc");
        vault.Value = null;   // cofre fora do ar depois da subida
        var context = new AuthorizationCodeReceivedContext(new DefaultHttpContext { RequestServices = services }, Scheme, options,
            new AuthenticationProperties()) { TokenEndpointRequest = new OpenIdConnectMessage() };

        var thrown = await Assert.That(async () => await options.Events.AuthorizationCodeReceived(context)).Throws<InvalidOperationException>();

        await Assert.That(context.TokenEndpointRequest!.ClientSecret).IsNull();
        await Assert.That(thrown!.Message).DoesNotContain("segredo-v1");
    }
}
