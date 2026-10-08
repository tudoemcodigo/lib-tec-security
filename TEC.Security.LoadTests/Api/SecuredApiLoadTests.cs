using TEC.Security.LoadTests.Infrastructure;

namespace TEC.Security.LoadTests.Api;

/// <summary>
/// Carga HTTP numa API protegida pelo TEC.Security hospedada em processo (Kestrel real em 127.0.0.1): JWT, API key,
/// autorização por permissão e tráfego hostil. Cada cenário tem o status esperado; qualquer outro conta como erro (inclusive
/// um ataque que passe: 200 onde se esperava 401).
/// </summary>
public class SecuredApiLoadTests
{
    [Test]
    [Category(TestCategories.LoadCi)]
    // Sozinho: os ConcurrencyTests (Parallel.ForAsync com muitos workers) saturam o thread pool do processo e, no runner
    // de 2 CPUs do CI, nenhuma requisição terminava dentro da janela medida (relatório com 0 requisições)
    [NotInParallel]
    public async Task SmokeLoad_AllScenarios_ExpectedStatusOnly()
    {
        await using var host = await SecuredApiHost.StartAsync();
        using var client = host.CreateClient(16);

        var report = await LoadRunner.RunAsync(client, new LoadOptions
        {
            Concurrency = 16,
            WarmUp = TimeSpan.FromSeconds(1),
            Duration = TimeSpan.FromSeconds(3),
            Scenarios = SecurityScenarios.Create(host),
        });
        LoadSettings.Report("API protegida — fumaça (CI)", report.ToText());

        await Assert.That(report.Requests).IsGreaterThan(100);
        await Assert.That(report.Errors).IsEqualTo(0).Because(report.ToText());
        await Assert.That(report.Scenarios.All(s => s.Requests > 0)).IsTrue().Because("todos os cenários devem ser exercitados");
    }

    [Test]
    [Explicit]
    [Category(TestCategories.LoadHeavy)]
    [NotInParallel(LoadSettings.HeavyExclusiveKey)]
    public async Task SustainedLoad_ErrorRateLatencyAndPermissionCacheWithinLimits()
    {
        // Store com 5 ms por consulta (banco): sem o cache, cada requisição autenticada pagaria essa latência
        await using var host = await SecuredApiHost.StartAsync(permissionLatency: TimeSpan.FromMilliseconds(5));
        int concurrency = LoadSettings.ApiConcurrency;
        using var client = host.CreateClient(concurrency);

        long memoryBefore = MemoryProbe.RetainedBytes();
        var report = await LoadRunner.RunAsync(client, new LoadOptions
        {
            Concurrency = concurrency,
            WarmUp = TimeSpan.FromSeconds(10),
            Duration = TimeSpan.FromSeconds(LoadSettings.ApiSeconds),
            Scenarios = SecurityScenarios.Create(host),
        });
        long memoryAfter = MemoryProbe.RetainedBytes();
        long storeCalls = host.PermissionStore.Calls;

        LoadSettings.Report("API protegida — carga sustentada",
            report.ToText() +
            $"Consultas ao store de permissões: {storeCalls:N0} · memória retida (cliente + servidor): {MemoryProbe.Megabytes(memoryBefore)} → {MemoryProbe.Megabytes(memoryAfter)}{Environment.NewLine}");

        // Limites generosos: o objetivo é pegar regressões grosseiras (erros, ataque aceito, travamento, vazamento), não medir a máquina
        await Assert.That(report.Errors).IsEqualTo(0).Because(report.ToText());
        await Assert.That(report.Latency.P99).IsLessThan(2_000);
        await Assert.That(memoryAfter - memoryBefore).IsLessThan(128L * 1024 * 1024);
        // Cada identidade distinta consulta o store uma vez (mais algumas consultas simultâneas na primeira vez)
        await Assert.That(storeCalls).IsLessThan(SecurityScenarios.Users * 4L).Because("o cache de permissões deve evitar consultas repetidas");
    }

    [Test]
    [Explicit]
    [Category(TestCategories.LoadHeavy)]
    [NotInParallel(LoadSettings.HeavyExclusiveKey)]
    public async Task HostileFlood_DoesNotStarveLegitimateTraffic()
    {
        await using var host = await SecuredApiHost.StartAsync();
        int concurrency = LoadSettings.ApiConcurrency;
        using var client = host.CreateClient(concurrency);
        var all = SecurityScenarios.Create(host);

        // Linha de base: só tráfego legítimo
        var baseline = await LoadRunner.RunAsync(client, new LoadOptions
        {
            Concurrency = concurrency,
            WarmUp = TimeSpan.FromSeconds(5),
            Duration = TimeSpan.FromSeconds(Math.Min(LoadSettings.ApiSeconds, 20)),
            Scenarios = SecurityScenarios.Select(all, "jwt-autorizado,api-key"),
        });

        // Ataque: 80% de credenciais forjadas (força bruta de API key, tokens adulterados, gigantes, alg:none) + 20% legítimo
        var flood = await LoadRunner.RunAsync(client, new LoadOptions
        {
            Concurrency = concurrency,
            WarmUp = TimeSpan.FromSeconds(5),
            Duration = TimeSpan.FromSeconds(Math.Min(LoadSettings.ApiSeconds, 30)),
            Scenarios = SecurityScenarios.Select(all,
                "jwt-autorizado:10,api-key:10,api-key-invalida:20,api-key-id-desconhecido:10,token-adulterado:20,token-outra-chave:10,token-gigante:5,token-alg-none:5,sem-credencial:10"),
        });

        var legitimate = flood.Scenarios.Where(s => s.Name is "jwt-autorizado" or "api-key").ToArray();
        double legitimateP99 = legitimate.Max(s => s.Latency.P99);
        LoadSettings.Report("API protegida — inundação de credenciais forjadas",
            "Linha de base (só legítimo):" + Environment.NewLine + baseline.ToText() +
            Environment.NewLine + "Durante o ataque:" + Environment.NewLine + flood.ToText());

        // Nenhum ataque aceito, nenhuma requisição legítima recusada, e o legítimo continua sendo atendido
        await Assert.That(flood.Errors).IsEqualTo(0).Because(flood.ToText());
        await Assert.That(legitimate.All(s => s.Requests > 0)).IsTrue();
        await Assert.That(legitimateP99).IsLessThan(Math.Max(baseline.Latency.P99 * 10, 250)).Because(flood.ToText());
    }
}
