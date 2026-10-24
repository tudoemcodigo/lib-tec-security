using System.Security.Claims;
using TEC.Core.Security;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests;

/// <summary>Normalização da identidade: tenant, papéis, permissões e descarte de claims reservados.</summary>
public class IdentityFactoryTests
{
    private const string ExternalTenant = "11111111-1111-1111-1111-111111111111";

    private static (SecurityIdentityFactory Factory, FakePermissionStore Store, TestOptionsMonitor<TenantOptions> Tenants) Create(
        bool requireTenant = false, bool rolesAsPermissions = true, bool tenantEnabled = true)
    {
        var tenants = new TenantOptions();
        tenants.Items["contoso"] = new TenantDefinition
        {
            Name = "Contoso",
            Enabled = tenantEnabled,
            IdentityProviders = { ["EntraId"] = [ExternalTenant] }
        };
        var monitor = new TestOptionsMonitor<TenantOptions>(tenants);
        var store = new FakePermissionStore();
        var factory = new SecurityIdentityFactory(new ConfigurationTenantRegistry(monitor), store,
            new TestOptionsMonitor<SecurityOptions>(new SecurityOptions { RequireTenant = requireTenant, RolesAsPermissions = rolesAsPermissions }));
        return (factory, store, monitor);
    }

    private static ExternalIdentity Identity(Action<List<Claim>>? claims = null, string[]? roles = null, string? tenant = ExternalTenant,
        PrincipalKind kind = PrincipalKind.User, string[]? scopes = null)
    {
        var source = new List<Claim> { new("email", "ana@contoso.com") };
        claims?.Invoke(source);
        return new ExternalIdentity
        {
            Scheme = "Funcionarios",
            Provider = "EntraId",
            UserId = "aaaaaaaa-0000-0000-0000-000000000001",
            Kind = kind,
            ExternalTenantId = tenant,
            Name = "Ana",
            Roles = roles ?? [],
            Scopes = scopes ?? [],
            SourceClaims = source
        };
    }

    [Test]
    public async Task Tenant_is_resolved_from_catalog_and_normalized_claims_are_created()
    {
        var (factory, _, _) = Create();

        var result = await factory.CreateAsync(Identity(roles: ["pedidos:ler"], scopes: ["api.read"]));
        var user = new SecurityUser(result.Value);

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(user.TenantId).IsEqualTo("contoso");
        await Assert.That(user.ExternalTenantId).IsEqualTo(ExternalTenant);
        await Assert.That(user.Kind).IsEqualTo(PrincipalKind.User);
        await Assert.That(user.HasPermission("pedidos:ler")).IsTrue();   // RolesAsPermissions
        await Assert.That(user.HasScope("api.read")).IsTrue();
        await Assert.That(result.Value.IsInRole("pedidos:ler")).IsTrue();   // RoleClaimType = tec_role
        await Assert.That(result.Value.FindFirst("email")?.Value).IsEqualTo("ana@contoso.com");
    }

    [Test]
    public async Task Tec_claims_from_the_provider_are_discarded()
    {
        var (factory, _, _) = Create();

        var result = await factory.CreateAsync(Identity(claims: c =>
        {
            c.Add(new Claim(TecClaimTypes.Permission, "admin:tudo"));
            c.Add(new Claim("TEC_PERM", "admin:tudo"));
            c.Add(new Claim(TecClaimTypes.Kind, nameof(PrincipalKind.System)));
            c.Add(new Claim(TecClaimTypes.TenantId, "outro-tenant"));
        }));
        var user = new SecurityUser(result.Value);

        await Assert.That(user.HasPermission("admin:tudo")).IsFalse();
        await Assert.That(user.Kind).IsEqualTo(PrincipalKind.User);
        await Assert.That(user.TenantId).IsEqualTo("contoso");
        await Assert.That(result.Value.FindAll(c => c.Type.Equals("TEC_PERM", StringComparison.Ordinal)).Count()).IsEqualTo(0);
    }

    [Test]
    public async Task Inactive_tenant_is_rejected()
    {
        var (factory, _, _) = Create(tenantEnabled: false);

        var result = await factory.CreateAsync(Identity());

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(result.Error!.Code).IsEqualTo(SecurityErrors.TenantNotAllowedCode);
    }

    [Test]
    public async Task RequireTenant_rejects_identity_without_registered_tenant()
    {
        var (factory, _, _) = Create(requireTenant: true);

        var unknown = await factory.CreateAsync(Identity(tenant: "22222222-2222-2222-2222-222222222222"));
        var none = await factory.CreateAsync(Identity(tenant: null));

        await Assert.That(unknown.IsFailure).IsTrue();
        await Assert.That(none.IsFailure).IsTrue();
    }

    [Test]
    public async Task Without_RequireTenant_identity_of_unknown_tenant_has_no_tenant()
    {
        var (factory, _, _) = Create();

        var result = await factory.CreateAsync(Identity(tenant: "22222222-2222-2222-2222-222222222222"));

        await Assert.That(result.IsSuccess).IsTrue();
        await Assert.That(new SecurityUser(result.Value).TenantId).IsNull();
    }

    [Test]
    public async Task Nonexistent_explicit_tenant_is_rejected()
    {
        var (factory, _, _) = Create();

        var result = await factory.CreateAsync(new ExternalIdentity
        {
            Scheme = "ApiKey", Provider = "ApiKey", UserId = "apikey:erp", Kind = PrincipalKind.Application, TenantId = "nao-existe"
        });

        await Assert.That(result.IsFailure).IsTrue();
    }

    [Test]
    public async Task Provider_cannot_create_system_identity()
    {
        var (factory, _, _) = Create();

        var result = await factory.CreateAsync(Identity(kind: PrincipalKind.System));

        await Assert.That(result.IsFailure).IsTrue();
    }

    [Test]
    [Arguments("")]
    [Arguments("id com espaço")]
    [Arguments("id\nquebra")]
    public async Task Invalid_identifier_is_rejected(string userId)
    {
        var (factory, _, _) = Create();
        var identity = Identity();

        var result = await factory.CreateAsync(new ExternalIdentity
        {
            Scheme = identity.Scheme, Provider = identity.Provider, UserId = userId, Kind = PrincipalKind.User
        });

        await Assert.That(result.IsFailure).IsTrue();
    }

    [Test]
    public async Task Malformed_roles_are_discarded_and_excess_is_rejected()
    {
        var (factory, _, _) = Create();

        var filtered = await factory.CreateAsync(Identity(roles: ["ok", "com espaço", "<script>", "ok"]));
        var inflated = await factory.CreateAsync(Identity(roles: [.. Enumerable.Range(0, 600).Select(i => $"papel-{i}")]));

        await Assert.That(new SecurityUser(filtered.Value).Roles.Count).IsEqualTo(1);
        await Assert.That(inflated.IsFailure).IsTrue();
    }

    [Test]
    public async Task Scopes_only_exist_on_user_identity()
    {
        var (factory, _, _) = Create();

        var result = await factory.CreateAsync(Identity(kind: PrincipalKind.Application, scopes: ["api.read"]));

        await Assert.That(new SecurityUser(result.Value).Scopes.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Permissions_come_from_store_and_RolesAsPermissions_can_be_disabled()
    {
        var (factory, store, _) = Create(rolesAsPermissions: false);
        store.Resolve = ctx => ctx.Roles.Contains("Gerente") ? ["pedidos:cancelar"] : [];

        var user = new SecurityUser((await factory.CreateAsync(Identity(roles: ["Gerente"]))).Value);

        await Assert.That(user.HasPermission("pedidos:cancelar")).IsTrue();
        await Assert.That(user.HasPermission("Gerente")).IsFalse();
    }

    [Test]
    public async Task Permission_store_failure_rejects_the_identity()
    {
        var (factory, store, _) = Create();
        store.Resolve = _ => throw new InvalidOperationException("banco fora");

        var result = await factory.CreateAsync(Identity(roles: ["Gerente"]));

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(result.Error!.Code).IsEqualTo(SecurityErrors.ProviderFailureCode);
    }

    [Test]
    public async Task Identity_without_normalization_mark_is_anonymous()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(TecClaimTypes.UserId, "x"), new Claim(TecClaimTypes.Kind, "User"), new Claim(TecClaimTypes.Permission, "admin")], "Outro"));

        var user = new SecurityUser(principal);

        await Assert.That(user.IsAuthenticated).IsFalse();
        await Assert.That(user.HasPermission("admin")).IsFalse();
    }

    [Test]
    public async Task Revalidation_reflects_disabled_tenant()
    {
        var (factory, _, tenants) = Create();
        var principal = (await factory.CreateAsync(Identity())).Value;

        var disabled = new TenantOptions();
        disabled.Items["contoso"] = new TenantDefinition { Enabled = false, IdentityProviders = { ["EntraId"] = [ExternalTenant] } };
        tenants.Set(disabled);

        var result = await factory.RevalidateAsync(principal);

        await Assert.That(result.IsFailure).IsTrue();
    }
}
