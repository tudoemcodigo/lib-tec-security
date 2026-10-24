using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Security.Abstractions;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests;

/// <summary>Cadastro de tenants: validação, vínculo com o provedor e recarga sem reinício.</summary>
public class TenantRegistryTests
{
    private const string Tid = "11111111-1111-1111-1111-111111111111";

    private static TenantOptions Options(params (string Id, bool Enabled, string[] External)[] tenants)
    {
        var options = new TenantOptions();
        foreach (var (id, enabled, external) in tenants)
            options.Items[id] = new TenantDefinition { Enabled = enabled, IdentityProviders = { ["EntraId"] = [.. external] } };
        return options;
    }

    [Test]
    public async Task External_id_is_resolved_case_insensitively()
    {
        var registry = new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(Options(("contoso", true, [Tid]))));

        await Assert.That(registry.FindByExternalId("entraid", Tid.ToUpperInvariant())?.Id).IsEqualTo("contoso");
        await Assert.That(registry.GetEnabledExternalIds("EntraId").Contains(Tid)).IsTrue();
    }

    [Test]
    public async Task Inactive_tenant_is_not_among_enabled_ids()
    {
        var registry = new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(Options(("contoso", false, [Tid]))));

        await Assert.That(registry.GetEnabledExternalIds("EntraId").Count).IsEqualTo(0);
        await Assert.That(registry.Find("contoso")!.Enabled).IsFalse();
    }

    [Test]
    public async Task Same_external_id_in_two_tenants_prevents_startup() =>
        await Assert.That(() => new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(
            Options(("contoso", true, [Tid]), ("fabrikam", true, [Tid]))))).Throws<InvalidOperationException>();

    [Test]
    [Arguments("com espaço")]
    [Arguments("-comeca-com-hifen")]
    [Arguments("x\n")]
    public async Task Malformed_tenant_id_prevents_startup(string id) =>
        await Assert.That(() => new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(Options((id, true, [Tid])))))
            .Throws<InvalidOperationException>();

    [Test]
    public async Task Valid_reload_enables_and_disables_without_restart()
    {
        var monitor = new TestOptionsMonitor<TenantOptions>(Options());
        var registry = new ConfigurationTenantRegistry(monitor);

        monitor.Set(Options(("contoso", true, [Tid])));
        bool enabled = registry.GetEnabledExternalIds("EntraId").Contains(Tid);
        monitor.Set(Options(("contoso", false, [Tid])));
        bool blocked = !registry.GetEnabledExternalIds("EntraId").Contains(Tid);

        await Assert.That(enabled).IsTrue();
        await Assert.That(blocked).IsTrue();
    }

    [Test]
    public async Task Invalid_reload_fails_closed_for_ambiguous_external_id_and_logs()
    {
        // Antes: a versão inteira era recusada e a anterior continuava valendo (SEC-03). Agora o id externo ambíguo deixa de
        // ser resolvido (nenhum dos dois tenants o recebe) e o restante da versão nova vale
        var monitor = new TestOptionsMonitor<TenantOptions>(Options(("contoso", true, [Tid])));
        var logs = new TestLoggerProvider();
        var registry = new ConfigurationTenantRegistry(monitor, new LoggerFactory([logs]).CreateLogger<ConfigurationTenantRegistry>());

        monitor.Set(Options(("contoso", true, [Tid]), ("fabrikam", true, [Tid])));

        await Assert.That(registry.FindByExternalId("EntraId", Tid)).IsNull();
        await Assert.That(registry.GetEnabledExternalIds("EntraId").Contains(Tid)).IsFalse();
        await Assert.That(registry.Find("fabrikam")).IsNotNull();
        await Assert.That(logs.Entries.Any(e => e.EventId == 3101)).IsTrue();
    }

    [Test]
    public async Task Invalid_reload_still_applies_deactivation_of_another_tenant()
    {
        // SEC-03: o operador desativa "contoso" e, na mesma edição, erra o id externo de "fabrikam". Antes a recarga era recusada
        // por inteiro e "contoso" continuava ativo
        const string Other = "22222222-2222-2222-2222-222222222222";
        var monitor = new TestOptionsMonitor<TenantOptions>(Options(("contoso", true, [Tid]), ("fabrikam", true, [Other])));
        var registry = new ConfigurationTenantRegistry(monitor);

        monitor.Set(Options(("contoso", false, [Tid]), ("fabrikam", true, [Other, "id externo com espaço"])));

        await Assert.That(registry.Find("contoso")!.Enabled).IsFalse();
        await Assert.That(registry.GetEnabledExternalIds("EntraId").Contains(Tid)).IsFalse();
        // A entrada com erro falha fechada: o tenant fica inativo até a correção
        await Assert.That(registry.Find("fabrikam")!.Enabled).IsFalse();
        await Assert.That(registry.GetEnabledExternalIds("EntraId").Contains(Other)).IsFalse();
    }

    [Test]
    public async Task Invalid_reload_removes_entries_with_malformed_or_repeated_ids()
    {
        var monitor = new TestOptionsMonitor<TenantOptions>(Options(("contoso", true, [Tid])));
        var registry = new ConfigurationTenantRegistry(monitor);

        var options = Options(("Contoso", true, [Tid]), ("contoso", true, []), ("com espaço", true, []));
        monitor.Set(options);

        await Assert.That(registry.Find("contoso")).IsNull();
        await Assert.That(registry.FindByExternalId("EntraId", Tid)).IsNull();
    }

    [Test]
    public async Task Catalog_comes_from_appsettings_with_reload()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:Tenants:contoso:Name"] = "Contoso",
            ["Security:Tenants:contoso:IdentityProviders:EntraId:0"] = Tid
        }).Build();
        var services = new ServiceCollection();
        services.AddTecSecurity(configuration);
        await using var provider = services.BuildServiceProvider();
        var registry = provider.GetRequiredService<ITenantRegistry>();

        bool before = registry.FindByExternalId("EntraId", Tid) is { Enabled: true };
        configuration["Security:Tenants:contoso:Enabled"] = "false";
        configuration.Reload();
        bool after = registry.FindByExternalId("EntraId", Tid) is { Enabled: true };

        await Assert.That(before).IsTrue();
        await Assert.That(after).IsFalse();
        await Assert.That(registry.Find("contoso")?.Name).IsEqualTo("Contoso");
    }
}
