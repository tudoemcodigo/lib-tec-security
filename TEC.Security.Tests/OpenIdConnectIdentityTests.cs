using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.Claims;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.OpenIdConnect;
using TEC.Security.OpenIdConnect.Internal;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests;

/// <summary>
/// Conversão dos claims OIDC em identidade: tipo (usuário x aplicação) por regras do esquema com padrão que falha fechado,
/// <c>resource_access</c> só do client alvo (inclusive no login web) e motivo de recusa sem o valor do token.
/// </summary>
public class OpenIdConnectIdentityTests
{
    private const string Keycloak = "https://auth.empresa.com/realms/corp";
    private const string Entra = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";

    private static OpenIdConnectApiOptions Api(string authority = Keycloak, Action<OpenIdConnectApiOptions>? configure = null)
    {
        var options = new OpenIdConnectApiOptions { Authority = authority, Audience = "api-pedidos" };
        configure?.Invoke(options);
        return options;
    }

    private static ExternalIdentity? Identity(OpenIdConnectApiOptions options, out string reason, params (string Type, string Value)[] claims) =>
        OpenIdConnectIdentity.FromClaims("Api", [.. claims.Select(c => new Claim(c.Type, c.Value))], options, null, out reason);

    // ---------------------------------------------------------------- Kind: sinais padrão

    [Test]
    [Arguments("idtyp", "app")]
    [Arguments("gty", "client-credentials")]
    public async Task Explicit_application_claim_is_application(string type, string value)
    {
        var identity = Identity(Api(), out _, ("sub", "cliente-1"), (type, value));

        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.Application);
    }

    [Test]
    [Arguments("sid", "sessao-1")]
    [Arguments("auth_time", "1767225600")]
    [Arguments("idtyp", "user")]
    public async Task User_session_claim_is_user(string type, string value)
    {
        var identity = Identity(Api(), out _, ("sub", "usuario-1"), (type, value));

        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.User);
    }

    [Test]
    [Arguments("azp")]
    [Arguments("client_id")]
    [Arguments("clientId")]
    [Arguments("cid")]
    [Arguments("appid")]
    public async Task Subject_equal_to_the_client_is_application(string clientClaim)
    {
        var identity = Identity(Api(), out _, ("sub", "servico-faturamento"), (clientClaim, "servico-faturamento"));

        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.Application);
    }

    [Test]
    public async Task Token_without_any_signal_is_rejected_by_default()
    {
        // Antes virava User e passava em Kinds = User mesmo sendo, por exemplo, uma conta de serviço não reconhecida
        var identity = Identity(Api(), out string reason, ("sub", "quem-sou-eu"), ("scope", "pedidos.ler"));

        await Assert.That(identity).IsNull();
        await Assert.That(reason).Contains("indeterminado");
    }

    [Test]
    [Arguments(OpenIdConnectUnresolvedKind.User, PrincipalKind.User)]
    [Arguments(OpenIdConnectUnresolvedKind.Application, PrincipalKind.Application)]
    public async Task Unresolved_policy_applies_only_without_signals(OpenIdConnectUnresolvedKind unresolved, PrincipalKind expected)
    {
        var options = Api(configure: o => o.Kind.Unresolved = unresolved);

        var withoutSignal = Identity(options, out _, ("sub", "auth0|123"));
        var application = Identity(options, out _, ("sub", "x@clients"), ("gty", "client-credentials"));

        await Assert.That(withoutSignal!.Kind).IsEqualTo(expected);
        await Assert.That(application!.Kind).IsEqualTo(PrincipalKind.Application);
    }

    [Test]
    public async Task Conflicting_user_and_application_signals_are_rejected()
    {
        var identity = Identity(Api(configure: o => o.Kind.Unresolved = OpenIdConnectUnresolvedKind.User), out string reason,
            ("sub", "x"), ("idtyp", "app"), ("sid", "sessao-1"));

        await Assert.That(identity).IsNull();
        await Assert.That(reason).Contains("ambíguo");
    }

    // ---------------------------------------------------------------- Kind: preferred_username não decide

    [Test]
    public async Task Editable_preferred_username_never_makes_a_user_an_application()
    {
        // Ataque: o usuário (ou o admin do tenant) muda o próprio username para imitar uma conta de serviço do Keycloak
        var user = Identity(Api(), out _, ("sub", "usuario-1"), ("sid", "sessao-1"), ("preferred_username", "service-account-faturamento"));
        var alone = Identity(Api(), out string reason, ("sub", "usuario-2"), ("preferred_username", "service-account-faturamento"));

        await Assert.That(user!.Kind).IsEqualTo(PrincipalKind.User);
        await Assert.That(alone).IsNull();
        await Assert.That(reason).Contains("indeterminado");
    }

    [Test]
    public async Task Keycloak_service_account_is_recognized_by_the_client_id_rule()
    {
        var options = Api(configure: o => o.Kind.ApplicationClaims.Add("client_id=*"));

        var serviceAccount = Identity(options, out _, ("sub", "6d4c2a8e-0000-0000-0000-000000000001"), ("azp", "faturamento"),
            ("client_id", "faturamento"), ("preferred_username", "service-account-faturamento"));
        var user = Identity(options, out _, ("sub", "6d4c2a8e-0000-0000-0000-000000000002"), ("azp", "portal"), ("sid", "sessao-1"));

        await Assert.That(serviceAccount!.Kind).IsEqualTo(PrincipalKind.Application);
        await Assert.That(user!.Kind).IsEqualTo(PrincipalKind.User);
    }

    [Test]
    public async Task Prefix_rule_matches_only_the_prefix()
    {
        var options = Api(configure: o => o.Kind.ApplicationClaims.Add("sub=svc-*"));

        var matched = Identity(options, out _, ("sub", "svc-faturamento"));
        var notMatched = Identity(options, out _, ("sub", "svcfaturamento"));

        await Assert.That(matched!.Kind).IsEqualTo(PrincipalKind.Application);
        await Assert.That(notMatched).IsNull();
    }

    // ---------------------------------------------------------------- Kind: Microsoft Entra ID

    [Test]
    public async Task Entra_application_token_without_idtyp_is_application()
    {
        // App-only do Entra ID sem o claim opcional idtyp: app roles em roles, sem scp, sub igual ao oid da aplicação
        var identity = Identity(Api(Entra), out _,
            ("sub", "22222222-2222-2222-2222-222222222222"), ("oid", "22222222-2222-2222-2222-222222222222"),
            ("azp", "33333333-3333-3333-3333-333333333333"), ("roles", "pedidos.ler.todos"),
            ("tid", "11111111-1111-1111-1111-111111111111"));

        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.Application);
        await Assert.That(identity.Scopes.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("/")]
    [Arguments(" ")]
    public async Task Entra_agent_token_with_empty_scp_is_application(string scp)
    {
        var identity = Identity(Api(Entra), out _, ("sub", "agente-1"), ("scp", scp));

        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.Application);
    }

    [Test]
    public async Task Entra_delegated_token_is_user()
    {
        var identity = Identity(Api(Entra), out _, ("sub", "pairwise-sub"), ("scp", "access_as_user"), ("azp", "spa-client"));

        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.User);
    }

    [Test]
    public async Task Entra_rule_applies_only_to_Entra_authorities_unless_configured()
    {
        (string, string)[] appOnly = [("sub", "22222222-2222-2222-2222-222222222222"), ("roles", "pedidos.ler.todos")];

        var keycloak = Identity(Api(Keycloak), out _, appOnly);
        var enabled = Identity(Api(Keycloak, o => o.Kind.UseEntraIdScpRule = true), out _, appOnly);
        var disabled = Identity(Api(Entra, o => o.Kind.UseEntraIdScpRule = false), out _, appOnly);

        await Assert.That(keycloak).IsNull();
        await Assert.That(enabled!.Kind).IsEqualTo(PrincipalKind.Application);
        await Assert.That(disabled).IsNull();
    }

    [Test]
    [Arguments("https://login.microsoftonline.com/x/v2.0", true)]
    [Arguments("https://login.microsoftonline.us/x/v2.0", true)]
    [Arguments("https://contoso.ciamlogin.com/x/v2.0", true)]
    [Arguments("https://login.microsoftonline.com.evil.test/x/v2.0", false)]
    [Arguments("https://auth.empresa.com/realms/corp", false)]
    public async Task Entra_authority_detection(string authority, bool expected) =>
        await Assert.That(KindClassifier.IsEntraIdAuthority(authority)).IsEqualTo(expected);

    // ---------------------------------------------------------------- regras inválidas impedem a subida

    [Test]
    [Arguments("preferred_username=service-account-*")]
    [Arguments("email=*@servicos.empresa.com")]
    [Arguments("tec_kind=Application")]
    [Arguments("sem-igual")]
    [Arguments("=app")]
    [Arguments("idtyp=")]
    [Arguments("id typ=app")]
    public async Task Invalid_kind_rule_prevents_registration(string rule)
    {
        var builder = new SecurityBuilder(new ServiceCollection(), new ConfigurationBuilder().Build());
        builder.AddAspNetCore();

        await Assert.That(() => builder.AddOpenIdConnectApi("Api", o =>
        {
            o.Authority = Keycloak;
            o.Audience = "api-pedidos";
            o.Kind.ApplicationClaims.Add(rule);
        })).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Undefined_unresolved_value_prevents_registration()
    {
        var builder = new SecurityBuilder(new ServiceCollection(), new ConfigurationBuilder().Build());
        builder.AddAspNetCore();

        await Assert.That(() => builder.AddOpenIdConnectApi("Api", o =>
        {
            o.Authority = Keycloak;
            o.Audience = "api-pedidos";
            o.Kind.Unresolved = (OpenIdConnectUnresolvedKind)99;
        })).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Kind_section_replaces_lists_and_reads_values()
    {
        var section = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Kind:ApplicationClaims:0"] = "client_id=*",
            ["Kind:UserClaims:0"] = "auth_time=*",
            ["Kind:ApplicationWhenSubjectIsClient"] = "false",
            ["Kind:UseEntraIdScpRule"] = "true",
            ["Kind:Unresolved"] = "user"
        }).Build().GetSection("Kind");
        var kind = new OpenIdConnectKindOptions();

        TEC.Security.OpenIdConnect.OpenIdConnectExtensions.ReadKind(section, kind, "Api");

        await Assert.That(string.Join('|', kind.ApplicationClaims)).IsEqualTo("client_id=*");
        await Assert.That(string.Join('|', kind.UserClaims)).IsEqualTo("auth_time=*");
        await Assert.That(kind.ApplicationWhenSubjectIsClient).IsFalse();
        await Assert.That(kind.UseEntraIdScpRule == true).IsTrue();
        await Assert.That(kind.Unresolved).IsEqualTo(OpenIdConnectUnresolvedKind.User);
    }

    [Test]
    [Arguments("Unresolved", "1")]
    [Arguments("Unresolved", "Talvez")]
    [Arguments("UseEntraIdScpRule", "sim")]
    [Arguments("ApplicationWhenSubjectIsClient", "")]
    public async Task Invalid_kind_section_value_prevents_registration(string key, string value)
    {
        var section = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Kind:" + key] = value })
            .Build().GetSection("Kind");

        await Assert.That(() => TEC.Security.OpenIdConnect.OpenIdConnectExtensions.ReadKind(section, new OpenIdConnectKindOptions(), "Api"))
            .Throws<InvalidOperationException>();
    }

    // ---------------------------------------------------------------- resource_access (Keycloak)

    private const string ResourceAccess = """
        {
          "realm-management": { "roles": ["manage-users", "realm-admin"] },
          "portal-web": { "roles": ["editor"] },
          "api-pedidos": { "roles": ["leitor-pedidos"] },
          "outra-app": { "roles": ["admin"] }
        }
        """;

    [Test]
    public async Task Web_login_reads_resource_access_only_from_its_own_client()
    {
        var web = new OpenIdConnectWebLoginOptions { Authority = Keycloak, ClientId = "portal-web" };
        Claim[] claims = [new("sub", "usuario-1"), new("resource_access", ResourceAccess, "JSON")];

        var identity = OpenIdConnectIdentity.FromWebLogin("Web", claims, web, null, out _);

        await Assert.That(string.Join('|', identity!.Roles)).IsEqualTo("editor");
        await Assert.That(identity.Kind).IsEqualTo(PrincipalKind.User);
    }

    [Test]
    public async Task Web_login_role_of_another_client_does_not_grant_permission()
    {
        // Ataque: o ID token traz client roles de realm-management (admin do realm); antes, sem audiência, todos entravam
        var web = new OpenIdConnectWebLoginOptions { Authority = Keycloak, ClientId = "portal-web" };
        Claim[] claims = [new("sub", "usuario-1"), new("sid", "sessao-1"), new("resource_access", ResourceAccess, "JSON")];
        var factory = new SecurityIdentityFactory(new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions())),
            new FakePermissionStore(), new TestOptionsMonitor<SecurityOptions>(new SecurityOptions()));

        var principal = await factory.CreateAsync(OpenIdConnectIdentity.FromWebLogin("Web", claims, web, null, out _)!);
        var user = new SecurityUser(principal.Value);

        await Assert.That(user.HasPermission("editor")).IsTrue();
        await Assert.That(user.HasPermission("manage-users")).IsFalse();
        await Assert.That(user.HasPermission("realm-admin")).IsFalse();
        await Assert.That(user.HasPermission("admin")).IsFalse();
        await Assert.That(user.IsInRole("manage-users")).IsFalse();
    }

    [Test]
    public async Task Web_login_is_always_user_even_with_application_like_claims()
    {
        var web = new OpenIdConnectWebLoginOptions { Authority = Entra, ClientId = "portal-web" };
        Claim[] claims = [new("sub", "portal-web"), new("azp", "portal-web"), new("preferred_username", "service-account-x")];

        var identity = OpenIdConnectIdentity.FromWebLogin("Web", claims, web, null, out _);

        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.User);
    }

    [Test]
    public async Task Without_target_client_no_resource_access_role_is_imported()
    {
        var options = new OpenIdConnectApiOptions { Authority = Keycloak };

        var identity = OpenIdConnectIdentity.FromClaims("Api", [new Claim("sub", "u1"), new Claim("sid", "s1"),
            new Claim("resource_access", ResourceAccess, "JSON")], options, null, out _);

        await Assert.That(identity!.Roles.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Resource_access_client_name_is_compared_exactly()
    {
        var options = Api();   // Audience = api-pedidos
        const string json = """{ "API-PEDIDOS": { "roles": ["admin"] }, "api-pedidos ": { "roles": ["admin2"] } }""";

        var identity = OpenIdConnectIdentity.FromClaims("Api", [new Claim("sub", "u1"), new Claim("sid", "s1"),
            new Claim("resource_access", json, "JSON")], options, null, out _);

        await Assert.That(identity!.Roles.Count).IsEqualTo(0);
    }

    // ---------------------------------------------------------------- tenant: motivo sem o valor do token

    [Test]
    [Arguments("tenant\nINFO acesso liberado")]
    [Arguments("cccccccc-0000-0000-0000-000000000099")]
    public async Task MultiTenant_rejection_reason_never_contains_the_tenant_value(string tid)
    {
        var options = Api(configure: o => o.MultiTenant = true);
        var registry = new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions()));

        var identity = OpenIdConnectIdentity.FromClaims("Api", [new Claim("sub", "u1"), new Claim("sid", "s1"), new Claim("tid", tid)],
            options, registry, out string reason);

        await Assert.That(identity).IsNull();
        await Assert.That(reason).DoesNotContain(tid);
        await Assert.That(reason).DoesNotContain("acesso liberado");
        await Assert.That(reason).Contains("caracteres");
    }
}
