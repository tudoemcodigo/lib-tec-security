using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Core.Security;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.Claims;
using TEC.Security.Configuration;
using TEC.Security.Context;
using TEC.Security.DependencyInjection;
using TEC.Security.Tenants;
using TEC.Security.Testing;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>
/// A identidade normalizada é provada pelo tipo criado no <see cref="SecurityIdentityFactory"/>, não pelo claim
/// <c>tec_normalized</c>: principal forjado com todos os claims <c>tec_*</c> continua anônimo, e os claims reservados ficam travados.
/// </summary>
public class NormalizedIdentityTests
{
    private static SecurityIdentityFactory Factory(SecurityOptions? options = null, ILogger<SecurityIdentityFactory>? logger = null) =>
        new(new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions())), new FakePermissionStore(),
            new TestOptionsMonitor<SecurityOptions>(options ?? new SecurityOptions()), logger);

    /// <summary>Principal montado à mão com todos os claims de uma identidade normalizada (inclusive a marca).</summary>
    internal static ClaimsPrincipal Forged(string scheme = "Web", string provider = "Teste") => new(new ClaimsIdentity(
        [
            new Claim(TecClaimTypes.Normalized, TecClaimTypes.NormalizedValue),
            new Claim(TecClaimTypes.UserId, "admin"),
            new Claim(TecClaimTypes.Kind, nameof(PrincipalKind.User)),
            new Claim(TecClaimTypes.Scheme, scheme),
            new Claim(TecClaimTypes.Provider, provider),
            new Claim(TecClaimTypes.Permission, "admin:tudo")
        ], "Forjado", TecClaimTypes.Name, TecClaimTypes.Role));

    [Test]
    public async Task Principal_with_every_tec_claim_but_not_created_by_the_factory_is_anonymous()
    {
        var factory = Factory();
        var forged = Forged();
        var context = new SecurityContext(factory);
        var user = new SecurityUser(forged);

        await Assert.That(user.IsAuthenticated).IsFalse();
        await Assert.That(user.HasPermission("admin:tudo")).IsFalse();
        await Assert.That(() => context.RunAs(forged)).Throws<InvalidOperationException>();
        await Assert.That((await factory.RevalidateAsync(forged)).IsFailure).IsTrue();
    }

    [Test]
    public async Task Normalized_identity_tec_claims_are_locked_after_creation()
    {
        var principal = (await Factory().CreateAsync(new ExternalIdentity
        {
            Scheme = "Api", Provider = "Teste", UserId = "u1", Kind = PrincipalKind.User, Roles = ["Leitor"]
        })).Value;
        var identity = (ClaimsIdentity)principal.Identity!;
        var role = identity.FindFirst(TecClaimTypes.Role)!;

        await Assert.That(() => identity.AddClaim(new Claim(TecClaimTypes.Permission, "admin:tudo"))).Throws<InvalidOperationException>();
        await Assert.That(() => identity.AddClaims([new Claim("TEC_TENANT", "outro")])).Throws<InvalidOperationException>();
        await Assert.That(() => identity.RemoveClaim(role)).Throws<InvalidOperationException>();
        await Assert.That(identity.TryRemoveClaim(role)).IsFalse();

        // Claims de outros tipos continuam livres (ex.: IClaimsTransformation da aplicação)
        identity.AddClaim(new Claim("claim-da-aplicacao", "x"));
        var user = new SecurityUser(principal);

        await Assert.That(user.HasPermission("admin:tudo")).IsFalse();
        await Assert.That(user.IsInRole("Leitor")).IsTrue();
        await Assert.That(principal.HasClaim("claim-da-aplicacao", "x")).IsTrue();
    }

    [Test]
    public async Task Clone_keeps_the_identity_normalized_but_a_manual_copy_does_not()
    {
        var principal = (await Factory().CreateAsync(new ExternalIdentity
        {
            Scheme = "Api", Provider = "Teste", UserId = "u1", Kind = PrincipalKind.User
        })).Value;

        var cloned = principal.Clone();
        var manualCopy = new ClaimsPrincipal(new ClaimsIdentity(principal.Identity));

        await Assert.That(new SecurityUser(cloned).IsAuthenticated).IsTrue();
        await Assert.That(() => ((ClaimsIdentity)cloned.Identity!).AddClaim(new Claim(TecClaimTypes.Permission, "x"))).Throws<InvalidOperationException>();
        await Assert.That(new SecurityUser(manualCopy).IsAuthenticated).IsFalse();
    }

    [Test]
    public async Task Identity_forged_by_another_middleware_gets_403_instead_of_access()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await TestApp.StartAsync(
            b => b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer)),
            a =>
            {
                a.UseAuthentication();
                // Outro mecanismo de autenticação (ou código da aplicação) entregando um principal com os claims tec_*
                a.Use(async (context, next) =>
                {
                    context.User = Forged();
                    await next();
                });
                a.UseAuthorization();
                a.MapGet("/admin", () => "ok").RequireTecAuthorization(permissions: "admin:tudo");
                a.MapGet("/qualquer", () => "ok");
            });

        var admin = await app.Client.GetAsync(new Uri("/admin", UriKind.Relative));
        var fallback = await app.Client.GetAsync(new Uri("/qualquer", UriKind.Relative));

        await Assert.That(admin.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(fallback.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- MultiTenant na revalidação

    [Test]
    public async Task Revalidation_keeps_the_multi_tenant_default_of_RolesAsPermissions()
    {
        var factory = Factory();
        var login = (await factory.CreateAsync(new ExternalIdentity
        {
            Scheme = "Web", Provider = "OpenIdConnect", UserId = "u1", Kind = PrincipalKind.User, MultiTenant = true, Roles = ["Admin"]
        })).Value;

        var revalidated = await factory.RevalidateAsync(login);

        await Assert.That(new SecurityUser(login).HasPermission("Admin")).IsFalse();
        await Assert.That(revalidated.IsSuccess).IsTrue();
        await Assert.That(revalidated.Value.HasClaim(TecClaimTypes.MultiTenant, TecClaimTypes.MultiTenantValue)).IsTrue();
        // Antes: a revalidação perdia o indicador e o papel do admin do tenant cliente virava permissão
        await Assert.That(new SecurityUser(revalidated.Value).HasPermission("Admin")).IsFalse();
        await Assert.That(new SecurityUser(revalidated.Value).IsInRole("Admin")).IsTrue();
    }

    [Test]
    public async Task Single_tenant_identity_and_forged_multi_tenant_source_claim_keep_the_default()
    {
        var factory = Factory();
        var login = (await factory.CreateAsync(new ExternalIdentity
        {
            Scheme = "Web", Provider = "OpenIdConnect", UserId = "u1", Kind = PrincipalKind.User, Roles = ["Admin"],
            // Claim reservado vindo do provedor: descartado, não liga o modo multi-tenant
            SourceClaims = [new Claim(TecClaimTypes.MultiTenant, TecClaimTypes.MultiTenantValue)]
        })).Value;

        var revalidated = (await factory.RevalidateAsync(login)).Value;

        await Assert.That(login.HasClaim(c => c.Type == TecClaimTypes.MultiTenant)).IsFalse();
        await Assert.That(new SecurityUser(login).HasPermission("Admin")).IsTrue();
        await Assert.That(new SecurityUser(revalidated).HasPermission("Admin")).IsTrue();
    }

    [Test]
    public async Task Explicit_RolesAsPermissions_in_multi_tenant_warns_once_per_process()
    {
        var logs = new TestLoggerProvider();
        using var loggerFactory = LoggerFactory.Create(b => b.AddProvider(logs));
        var factory = Factory(new SecurityOptions { RolesAsPermissions = true }, loggerFactory.CreateLogger<SecurityIdentityFactory>());
        var identity = new ExternalIdentity
        {
            Scheme = "Web", Provider = "OpenIdConnect", UserId = "u1", Kind = PrincipalKind.User, MultiTenant = true, Roles = ["Admin"]
        };

        var first = (await factory.CreateAsync(identity)).Value;
        _ = await factory.CreateAsync(identity);
        _ = await factory.RevalidateAsync(first);

        await Assert.That(new SecurityUser(first).HasPermission("Admin")).IsTrue();
        await Assert.That(logs.Entries.Count(e => e.EventId == 3403)).IsEqualTo(1);
    }
}
