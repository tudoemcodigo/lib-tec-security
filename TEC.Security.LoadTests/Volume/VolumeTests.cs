using System.Diagnostics;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Core.Security;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.LoadTests.Infrastructure;
using TEC.Security.Tenants;

namespace TEC.Security.LoadTests.Volume;

/// <summary>
/// Volume: cadastros e caches muito maiores que o uso típico, verificando custo de montagem, consultas corretas e memória
/// limitada. Tamanhos em TEC_CARGA_TENANTS e TEC_CARGA_IDENTIDADES.
/// </summary>
[Explicit]
[Category(TestCategories.LoadHeavy)]
[NotInParallel(LoadSettings.HeavyExclusiveKey)]
public class VolumeTests
{
    [Test]
    public async Task TenantRegistry_LargeCatalog_BuildLookupAndReload()
    {
        int count = LoadSettings.Tenants;
        static TenantOptions Catalog(int count, int disabled)
        {
            var options = new TenantOptions();
            for (int i = 0; i < count; i++)
            {
                options.Items[$"tenant-{i}"] = new TenantDefinition
                {
                    Name = $"Empresa {i}",
                    Enabled = i != disabled,
                    IdentityProviders = { ["EntraId"] = [Tid(i, 0), Tid(i, 1)] }
                };
            }

            return options;
        }

        var first = Catalog(count, disabled: -1);
        var second = Catalog(count, disabled: 7);
        var monitor = new ManualOptionsMonitor<TenantOptions>(first);

        long memoryBefore = MemoryProbe.RetainedBytes();
        var watch = Stopwatch.StartNew();
        using var registry = new ConfigurationTenantRegistry(monitor);
        var buildTime = watch.Elapsed;
        long memoryAfter = MemoryProbe.RetainedBytes();

        // Consultas: acertos (com outra caixa), erros e o conjunto de ids liberados
        const int lookups = 1_000_000;
        var random = new Random(3);
        int wrong = 0;
        watch.Restart();
        for (int n = 0; n < lookups; n++)
        {
            int i = random.Next(count);
            var tenant = registry.FindByExternalId("ENTRAID", Tid(i, n & 1).ToUpperInvariant());
            if (tenant?.Id != $"tenant-{i}")
                wrong++;
        }

        var lookupTime = watch.Elapsed;
        int enabled = registry.GetEnabledExternalIds("EntraId").Count;

        // Recarga do cadastro inteiro com leituras simultâneas
        using var stop = new CancellationTokenSource();
        long concurrentReads = 0;
        var readers = Enumerable.Range(0, Environment.ProcessorCount).Select(r => Task.Run(() =>
        {
            var local = new Random(r);
            while (!stop.IsCancellationRequested)
            {
                int i = local.Next(count);
                if (registry.FindByExternalId("EntraId", Tid(i, 0))?.Id != $"tenant-{i}")
                    Interlocked.Increment(ref wrong);
                Interlocked.Increment(ref concurrentReads);
            }
        })).ToArray();
        watch.Restart();
        monitor.Set(second);
        var reloadTime = watch.Elapsed;
        await stop.CancelAsync();
        await Task.WhenAll(readers);

        double perTenant = (memoryAfter - memoryBefore) / (double)count;
        var report = new StringBuilder();
        report.AppendLine(CultureInfo.InvariantCulture, $"Tenants: {count:N0} (2 ids externos cada)");
        report.AppendLine(CultureInfo.InvariantCulture, $"Montagem: {buildTime.TotalMilliseconds:N0} ms · recarga: {reloadTime.TotalMilliseconds:N0} ms ({Interlocked.Read(ref concurrentReads):N0} leituras simultâneas)");
        report.AppendLine(CultureInfo.InvariantCulture, $"Memória retida do cadastro: {MemoryProbe.Megabytes(memoryAfter - memoryBefore)} (~{perTenant:N0} bytes/tenant)");
        report.AppendLine(CultureInfo.InvariantCulture, $"Consultas: {lookups / lookupTime.TotalSeconds:N0}/s ({lookupTime.TotalMilliseconds * 1000 / lookups:F2} µs cada)");
        LoadSettings.Report("Volume — cadastro de tenants", report.ToString());

        await Assert.That(wrong).IsEqualTo(0);
        await Assert.That(enabled).IsEqualTo(count * 2);
        await Assert.That(registry.GetEnabledExternalIds("EntraId").Count).IsEqualTo(count * 2 - 2).Because("o tenant desativado na recarga sai da lista");
        await Assert.That(registry.Find("tenant-7")!.Enabled).IsFalse();
        await Assert.That(buildTime).IsLessThan(TimeSpan.FromSeconds(60)).Because(report.ToString());
        await Assert.That(lookups / lookupTime.TotalSeconds).IsGreaterThan(200_000).Because(report.ToString());
        await Assert.That(perTenant).IsLessThan(4_096).Because(report.ToString());
    }

    [Test]
    public async Task PermissionCache_ManyDistinctIdentities_MemoryBounded()
    {
        int identities = LoadSettings.Identities;
        const int cacheLimit = 50_000;

        var configuration = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        services.AddSingleton(new PermissionStoreLatency(TimeSpan.Zero));
        services.AddTecSecurity(configuration, security => security.UsePermissionStore<SimulatedDatabasePermissionStore>());
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<SecurityIdentityFactory>();
        var store = provider.GetRequiredService<SimulatedDatabasePermissionStore>();

        async Task FeedAsync(int from, int to) =>
            await Parallel.ForAsync(from, to, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, async (i, ct) =>
            {
                var result = await factory.CreateAsync(new ExternalIdentity
                {
                    Scheme = "Test", Provider = "Test", UserId = $"identidade-{i:D7}", Kind = PrincipalKind.Application, Roles = ["leitor", $"grupo-{i % 50}"]
                }, ct);
                if (result.IsFailure)
                    throw new InvalidOperationException("identidade recusada");
            });

        long baseline = MemoryProbe.RetainedBytes();
        var watch = Stopwatch.StartNew();
        await FeedAsync(0, cacheLimit);
        long atLimit = MemoryProbe.RetainedBytes();
        await FeedAsync(cacheLimit, identities);
        var elapsed = watch.Elapsed;
        // A compactação do MemoryCache roda em segundo plano: dá tempo para ela terminar antes de medir
        await Task.Delay(TimeSpan.FromSeconds(2));
        long atEnd = MemoryProbe.RetainedBytes();

        var report = new StringBuilder();
        report.AppendLine(CultureInfo.InvariantCulture, $"Identidades distintas: {identities:N0} (limite do cache: {cacheLimit:N0}) · {identities / elapsed.TotalSeconds:N0} normalizações/s");
        report.AppendLine(CultureInfo.InvariantCulture, $"Memória retida: início {MemoryProbe.Megabytes(baseline)} · no limite {MemoryProbe.Megabytes(atLimit)} · fim {MemoryProbe.Megabytes(atEnd)}");
        report.AppendLine(CultureInfo.InvariantCulture, $"Consultas ao store: {store.Calls:N0}");
        LoadSettings.Report("Volume — cache de permissões com identidades distintas", report.ToString());

        // Passado o limite, o cache para de crescer: a memória no fim fica perto da medida no limite
        long cacheAtLimit = Math.Max(atLimit - baseline, 1);
        await Assert.That(atEnd - atLimit).IsLessThan(Math.Max(16L * 1024 * 1024, cacheAtLimit / 2)).Because(report.ToString());
        await Assert.That(store.Calls).IsGreaterThanOrEqualTo(identities);
    }

    [Test]
    public async Task InflatedIdentities_AtAndAboveItemLimit()
    {
        var configuration = new ConfigurationBuilder().Build();
        var services = new ServiceCollection();
        services.AddTecSecurity(configuration);
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<SecurityIdentityFactory>();

        string[] atLimit = [.. Enumerable.Range(0, SecurityRules.MaxItemsPerIdentity).Select(i => $"papel:{i:D4}")];
        // Um milhão de papéis (token inflado): recusado ao passar do limite, sem processar o resto
        string[] huge = [.. Enumerable.Range(0, 1_000_000).Select(i => $"papel:{i:D7}")];

        ExternalIdentity Identity(int i, string[] roles) => new()
        {
            Scheme = "Test", Provider = "Test", UserId = $"usuario-{i}", Kind = PrincipalKind.User, Roles = roles
        };

        const int creations = 5_000;
        var watch = Stopwatch.StartNew();
        int accepted = 0;
        for (int i = 0; i < creations; i++)
        {
            var result = await factory.CreateAsync(Identity(i, atLimit));
            if (result.IsSuccess && new SecurityUser(result.Value).Roles.Count == SecurityRules.MaxItemsPerIdentity)
                accepted++;
        }

        var atLimitTime = watch.Elapsed;
        watch.Restart();
        var rejected = await factory.CreateAsync(Identity(0, huge));
        var hugeTime = watch.Elapsed;

        LoadSettings.Report("Volume — identidades no limite de itens",
            string.Create(CultureInfo.InvariantCulture,
                $"{creations:N0} identidades com {SecurityRules.MaxItemsPerIdentity} papéis: {atLimitTime.TotalMilliseconds / creations:F3} ms cada · " +
                $"identidade com 1 milhão de papéis recusada em {hugeTime.TotalMilliseconds:F2} ms{Environment.NewLine}"));

        await Assert.That(accepted).IsEqualTo(creations);
        await Assert.That(rejected.IsFailure).IsTrue();
        await Assert.That(atLimitTime.TotalMilliseconds / creations).IsLessThan(10);
        await Assert.That(hugeTime).IsLessThan(TimeSpan.FromMilliseconds(500));
    }

    private static string Tid(int tenant, int index) => new Guid(tenant, (short)index, 0, 0, 0, 0, 0, 0, 0, 0, 1).ToString("D");
}
