using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.Claims;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect;
using TEC.Security.OpenIdConnect.Internal;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tokens;
using TEC.Vault.Abstractions;

namespace TEC.Security.Tests;

public class SecurityIssueRegressionTests
{
    // Issue #2: Registro M2M em DI resolve IAccessTokenProvider e cria HttpClient com sucesso
    [Test]
    public async Task Issue2_M2M_DI_Registration_Resolves_IAccessTokenProvider()
    {
        var services = new ServiceCollection();
        var config = new ConfigurationBuilder().Build();

        services.AddTecSecurity(config, s => s.AddOpenIdConnectClient(o =>
        {
            o.Authority = "https://auth.empresa.com/realms/corp";
            o.ClientId = "meu-servico";
            o.ClientSecret = "segredo";
        }));

        services.AddHttpClient("EstoqueClient").AddOpenIdConnectAccessToken(o =>
        {
            o.Scopes.Add("estoque.consultar");
            o.AllowedHosts.Add("estoque.empresa.com");
        });

        using var sp = services.BuildServiceProvider();
        var clientFactory = sp.GetRequiredService<IHttpClientFactory>();
        var client = clientFactory.CreateClient("EstoqueClient");
        await Assert.That(client).IsNotNull();

        var provider = sp.GetRequiredService<IAccessTokenProvider>();
        await Assert.That(provider).IsNotNull();
    }

    // Issue #3: PrivateKeyJwt sem suporte lança NotSupportedException no construtor
    [Test]
    public async Task Issue3_PrivateKeyJwt_Throws_NotSupportedException()
    {
        var options = new OpenIdConnectClientOptions
        {
            Authority = "https://auth.empresa.com",
            ClientId = "meu-servico",
            AuthType = OpenIdConnectM2MAuthType.PrivateKeyJwt
        };

        using var http = new HttpClient();
        Assert.Throws<NotSupportedException>(() => new OpenIdConnectAccessTokenProvider(http, options));
    }

    // Issue #4: Tenant por emissor funciona mesmo sem MultiTenant
    [Test]
    public async Task Issue4_Tenant_By_Issuer_Works_Without_MultiTenant()
    {
        var registry = new InMemoryTenantRegistry(new Dictionary<string, TenantInfo>(StringComparer.OrdinalIgnoreCase)
        {
            ["https://auth.empresa.com/realms/corp"] = new TenantInfo("corp-tenant", "contoso", true)
        });

        var options = new OpenIdConnectApiOptions
        {
            Authority = "https://auth.empresa.com/realms/corp",
            Audience = "minha-api",
            MultiTenant = false
        };

        var claims = new[]
        {
            new Claim("sub", "user-123"),
            new Claim("sid", "sessao-1"),
            new Claim("iss", "https://auth.empresa.com/realms/corp")
        };

        var identity = OpenIdConnectIdentity.FromClaims("Test", claims, options, registry, out string reason);
        await Assert.That(identity).IsNotNull();
        await Assert.That(identity!.TenantId).IsEqualTo("corp-tenant");
    }

    // Issue #6: Web Login ClientSecretName sem ISecretReader lança exceção explicita
    [Test]
    public async Task Issue6_WebLogin_ClientSecretName_Without_Vault_Throws()
    {
        var builder = new SecurityBuilder(new ServiceCollection(), new ConfigurationBuilder().Build());
        builder.AddAspNetCore();
        builder.AddOpenIdConnectWebLogin("WebLogin", o =>
        {
            o.Authority = "https://auth.empresa.com";
            o.ClientId = "web-client";
            o.ClientSecretName = "segredo-web";
        });

        var sp = builder.Services.BuildServiceProvider();
        var monitor = sp.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>>();

        Assert.Throws<InvalidOperationException>(() => monitor.Get("WebLogin.oidc"));
    }

    // Issue #7: RequireHttpsMetadata = false aceita loopback, recusa remoto
    [Test]
    public async Task Issue7_RequireHttpsMetadata_Allows_Loopback_Rejects_Remote()
    {
        var optionsLocal = new JwtBearerOptions
        {
            Authority = "http://localhost:8080/realms/test",
            RequireHttpsMetadata = false
        };
        JwtHardening.ApplyDefaults(optionsLocal, 256 * 1024, isDevelopment: true);
        optionsLocal.RequireHttpsMetadata = false;
        optionsLocal.TokenValidationParameters.ValidAudience = "test";
        optionsLocal.TokenValidationParameters.ValidIssuer = "http://localhost:8080/realms/test";

        // Localhost loopback não deve lançar exceção
        JwtHardening.Enforce(optionsLocal, "LocalScheme");

        var optionsRemote = new JwtBearerOptions
        {
            Authority = "http://remote.empresa.com/realms/test",
            RequireHttpsMetadata = false
        };
        JwtHardening.ApplyDefaults(optionsRemote, 256 * 1024, isDevelopment: true);
        optionsRemote.RequireHttpsMetadata = false;
        optionsRemote.TokenValidationParameters.ValidAudience = "test";
        optionsRemote.TokenValidationParameters.ValidIssuer = "http://remote.empresa.com/realms/test";

        // Remoto com HTTP deve falhar
        Assert.Throws<InvalidOperationException>(() => JwtHardening.Enforce(optionsRemote, "RemoteScheme"));
    }

    // Issue #8: resource_access de outros clients do Keycloak não vazam
    [Test]
    public async Task Issue8_ResourceAccess_Is_Isolated_To_API_Client()
    {
        var options = new OpenIdConnectApiOptions
        {
            Authority = "https://auth.empresa.com",
            Audience = "api-pedidos"
        };

        string resourceAccessJson = """
        {
            "app-financeiro": { "roles": ["admin-financeiro"] },
            "api-pedidos": { "roles": ["leitor-pedidos"] }
        }
        """;

        var claims = new[]
        {
            new Claim("sub", "user-123"),
            new Claim("sid", "sessao-1"),
            new Claim("resource_access", resourceAccessJson)
        };

        var identity = OpenIdConnectIdentity.FromClaims("Test", claims, options, null, out _);
        await Assert.That(identity).IsNotNull();
        await Assert.That(identity!.Roles).Contains("leitor-pedidos");
        await Assert.That(identity!.Roles).DoesNotContain("admin-financeiro");
    }

    // Issue #9: Classificação User vs Application por regras do esquema, nunca pelo preferred_username
    [Test]
    public async Task Issue9_Classification_Keycloak_M2M_Is_Application()
    {
        var options = new OpenIdConnectApiOptions { Authority = "https://auth.empresa.com", Audience = "api" };
        options.Kind.ApplicationClaims.Add("client_id=*");   // receita do Keycloak: o mapper da conta de serviço emite client_id

        var m2mClaims = new[]
        {
            new Claim("sub", "6d4c2a8e-0000-0000-0000-000000000001"),
            new Claim("azp", "minha-app"),
            new Claim("client_id", "minha-app"),
            new Claim("preferred_username", "service-account-minha-app"),
            new Claim("realm_access", """{"roles": ["default-roles-corp"]}""")
        };

        var identity = OpenIdConnectIdentity.FromClaims("Test", m2mClaims, options, null, out _);
        await Assert.That(identity).IsNotNull();
        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.Application);

        var userClaims = new[]
        {
            new Claim("sub", "auth0|999"),
            new Claim("sid", "sessao-1"),
            new Claim("scope", "read:messages")
        };

        var userIdentity = OpenIdConnectIdentity.FromClaims("Test", userClaims, options, null, out _);
        await Assert.That(userIdentity).IsNotNull();
        await Assert.That(userIdentity!.Kind).IsEqualTo(PrincipalKind.User);
    }

    // Issue #10: JwtHardening bloqueia delegates não autorizados
    [Test]
    public async Task Issue10_JwtHardening_Rejects_Custom_Delegates()
    {
        var options = new JwtBearerOptions { Authority = "https://auth.empresa.com", RequireHttpsMetadata = true };
        JwtHardening.ApplyDefaults(options, 256 * 1024, isDevelopment: true);
        options.TokenValidationParameters.ValidAudience = "api";
        options.TokenValidationParameters.ValidIssuer = "https://auth.empresa.com";

        // SignatureValidatorUsingConfiguration
        options.TokenValidationParameters.SignatureValidatorUsingConfiguration = (t, p, c) => null!;
        Assert.Throws<InvalidOperationException>(() => JwtHardening.Enforce(options, "Test"));

        // Limpa e testa AudienceValidator
        options.TokenValidationParameters.SignatureValidatorUsingConfiguration = null;
#pragma warning disable CA5405
        options.TokenValidationParameters.AudienceValidator = (_, _, _) => true;
#pragma warning restore CA5405
        Assert.Throws<InvalidOperationException>(() => JwtHardening.Enforce(options, "Test"));
    }

    // Issue #11: RolesAsPermissions default false em MultiTenant
    [Test]
    public async Task Issue11_RolesAsPermissions_Defaults_To_False_In_MultiTenant()
    {
        var identity = new ExternalIdentity
        {
            Scheme = "Test",
            Provider = "OpenIdConnect",
            UserId = "user-1",
            Kind = PrincipalKind.User,
            MultiTenant = true,
            Roles = new[] { "Admin" }
        };

        var factory = new SecurityIdentityFactory(
            new InMemoryTenantRegistry(new Dictionary<string, TenantInfo>()),
            new FakePermissionStore(),
            new TestOptionsMonitor<SecurityOptions>(new SecurityOptions()),
            null);

        var result = await factory.CreateAsync(identity);
        await Assert.That(result.IsSuccess).IsTrue();
        var user = new SecurityUser(result.Value);
        await Assert.That(user.Permissions).DoesNotContain("Admin");
    }

    // Issue #12: TenantClaim e RoleClaimType exclusivos
    [Test]
    public async Task Issue12_Exclusive_TenantClaim_And_RoleClaim()
    {
        var options = new OpenIdConnectApiOptions
        {
            Authority = "https://auth.empresa.com",
            Audience = "api",
            TenantClaim = "custom_tenant",
            RoleClaimType = "custom_role"
        };

        var claims = new[]
        {
            new Claim("sub", "user-1"),
            new Claim("sid", "sessao-1"),
            new Claim("tenant", "invalido"),
            new Claim("custom_tenant", "correto"),
            new Claim("role", "role-invalida"),
            new Claim("custom_role", "role-correta")
        };

        var identity = OpenIdConnectIdentity.FromClaims("Test", claims, options, null, out _);
        await Assert.That(identity).IsNotNull();
        await Assert.That(identity!.ExternalTenantId).IsEqualTo("correto");
        await Assert.That(identity!.Roles).Contains("role-correta");
        await Assert.That(identity!.Roles).DoesNotContain("role-invalida");
    }

    // Issue #13: M2M exige HTTPS no endpoint e sanitiza corpo de erro
    [Test]
    public async Task Issue13_M2M_Requires_Https_And_Sanitizes_Error()
    {
        var optionsHttp = new OpenIdConnectClientOptions
        {
            TokenEndpoint = "http://insecure.empresa.com/oauth/token",
            ClientId = "app",
            ClientSecret = "secret"
        };
        using var client = new HttpClient();
        Assert.Throws<InvalidOperationException>(() => new OpenIdConnectAccessTokenProvider(client, optionsHttp));

        // Handler que devolve 500 com corpo sensível
        var fakeHandler = new FakeErrorHttpHandler(HttpStatusCode.InternalServerError, "DB Connection String: secret-password");
        using var errorClient = new HttpClient(fakeHandler);
        var optionsValid = new OpenIdConnectClientOptions
        {
            TokenEndpoint = "https://auth.empresa.com/oauth/token",
            ClientId = "app",
            ClientSecret = "secret"
        };
        using var provider = new OpenIdConnectAccessTokenProvider(errorClient, optionsValid);
        var ex = await Assert.That(async () => await provider.GetTokenAsync(new[] { "scope1" }))
            .ThrowsExactly<SecurityTokenAcquisitionException>();
        await Assert.That(ex!.Message).DoesNotContain("secret-password");
    }

    private sealed class InMemoryTenantRegistry(Dictionary<string, TenantInfo> externalToTenant) : ITenantRegistry
    {
        public TenantInfo? Find(string tenantId) => externalToTenant.Values.FirstOrDefault(t => t.Id == tenantId);
        public TenantInfo? FindByExternalId(string provider, string externalTenantId) =>
            externalToTenant.TryGetValue(externalTenantId, out var info) ? info : null;
        public IReadOnlySet<string> GetEnabledExternalIds(string provider) =>
            externalToTenant.Where(kvp => kvp.Value.Enabled).Select(kvp => kvp.Key).ToHashSet();
    }

    private sealed class FakeErrorHttpHandler(HttpStatusCode code, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var res = new HttpResponseMessage(code)
            {
                Content = new StringContent(body)
            };
            return Task.FromResult(res);
        }
    }
}
