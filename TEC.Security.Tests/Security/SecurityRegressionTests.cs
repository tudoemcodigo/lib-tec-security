using TEC.Security.Configuration;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests.Security;

/// <summary>Regressões de falhas encontradas pelos testes de segurança (fuzzing, DoS, vazamento e tempo constante).</summary>
public class SecurityRegressionTests
{
    [Test]
    [Arguments("tid-\u017F", "tid-S")]       // s longo (U+017F): ToUpperInvariant vira "S"
    [Arguments("tid-\u212A", "tid-k")]       // sinal de Kelvin (U+212A): ToLowerInvariant vira "k"
    [Arguments("tid-\u0131", "tid-I")]       // i sem ponto do turco (U+0131): ToUpperInvariant vira "I"
    [Arguments("tid-contoso\n", "tid-contoso")]
    [Arguments(" tid-contoso", "tid-contoso")]
    public async Task TenantRegistry_ExternalIdOutsideAscii_NeverResolvesToAnotherTenant(string presented, string registered)
    {
        // Achado do fuzzing (FuzzingTests.TenantRegistry_*): a chave do índice usava ToUpperInvariant sem validar o formato,
        // e "tid-" + U+017F resolvia para o tenant cadastrado com "tid-S"
        var options = new TenantOptions();
        options.Items["contoso"] = new TenantDefinition { IdentityProviders = { ["Test"] = [registered] } };
        using var registry = new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(options));

        await Assert.That(registry.FindByExternalId("Test", registered.ToUpperInvariant())?.Id).IsEqualTo("contoso");
        await Assert.That(registry.FindByExternalId("Test", presented)).IsNull();
        await Assert.That(registry.FindByExternalId("T\u0435st", registered)).IsNull();
    }
}
