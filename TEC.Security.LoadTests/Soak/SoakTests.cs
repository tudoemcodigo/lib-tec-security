using System.Diagnostics;
using System.Globalization;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.Claims;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.LoadTests.Infrastructure;
using TEC.Security.Tenants;
using TEC.Security.Tokens;

namespace TEC.Security.LoadTests.Soak;

/// <summary>
/// Soak: carga mista contínua por minutos (API keys válidas e inválidas, normalização de identidades com cache de permissões,
/// cadastro de tenants com recargas, <c>RunAs</c>, token de serviço e handler de saída), verificando que memória, handles e vazão
/// ficam estáveis (sem vazamentos nem degradação). Duração em TEC_CARGA_SOAK_SEGUNDOS (padrão 120 s).
/// </summary>
[Explicit]
[Category(TestCategories.LoadHeavy)]
[NotInParallel(LoadSettings.HeavyExclusiveKey)]
public class SoakTests
{
    private sealed record Sample(double Seconds, long Operations, long RetainedBytes, int Handles);

    [Test]
    public async Task MixedWorkload_MemoryHandlesAndThroughputStayStable()
    {
        var duration = TimeSpan.FromSeconds(LoadSettings.SoakSeconds);
        var interval = TimeSpan.FromSeconds(Math.Clamp(LoadSettings.SoakSeconds / 24.0, 2, 30));

        var apiKey = ApiKeyGenerator.Generate("erp-contoso");
        string tamperedKey = apiKey.Key[..^10] + (apiKey.Key[^10] == 'A' ? 'B' : 'A') + apiKey.Key[^9..];
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:Tenants:contoso:IdentityProviders:Test:0"] = "tid-contoso",
            ["Security:ApiKeys:Keys:erp-contoso:Hash"] = apiKey.Hash,
            ["Security:ApiKeys:Keys:erp-contoso:TenantId"] = "contoso",
            ["Security:ApiKeys:Keys:erp-contoso:Permissions:0"] = "pedidos:ler",
            ["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = DateTimeOffset.UtcNow.AddDays(1).ToString("O", CultureInfo.InvariantCulture)
        }).Build();
        var services = new ServiceCollection();
        services.AddSingleton(new PermissionStoreLatency(TimeSpan.Zero));
        services.AddTecSecurity(configuration, security => security.UsePermissionStore<SimulatedDatabasePermissionStore>(TimeSpan.FromSeconds(30)));
        await using var provider = services.BuildServiceProvider();

        var validator = provider.GetRequiredService<ApiKeyValidator>();
        var factory = provider.GetRequiredService<SecurityIdentityFactory>();
        var context = provider.GetRequiredService<ISecurityContext>();
        var system = (await context.CreateSystemPrincipalAsync("fechamento-mensal", "contoso")).Value;

        var tenantMonitor = new ManualOptionsMonitor<TenantOptions>(Tenants(enabled: true));
        using var registry = new ConfigurationTenantRegistry(tenantMonitor);
        // Tokens de 6 minutos: renovados a cada ~1 minuto (5 minutos antes de expirar)
        using var tokens = new CountingTokenProvider(TimeProvider.System, TimeSpan.FromMinutes(6), TimeSpan.FromMilliseconds(1));
        var handlerOptions = new AccessTokenHandlerOptions { Scopes = { "api://contoso/.default" }, AllowedHosts = { "api.contoso.com" } };
        using var invoker = new HttpMessageInvoker(new AccessTokenHandler(tokens, handlerOptions) { InnerHandler = new OkHandler() });

        long operations = 0;
        long failures = 0;
        using var stop = new CancellationTokenSource(duration);

        async Task WorkerAsync(int id)
        {
            var random = new Random(id);
            await using var scope = provider.CreateAsyncScope();
            var user = scope.ServiceProvider.GetRequiredService<ISecurityUser>();
            string[] scopeSet = [$"api://servico-{id % 8}/.default"];

            while (!stop.IsCancellationRequested)
            {
                bool ok = true;
                switch (random.Next(100))
                {
                    case < 20:
                        // Uma em cada quatro chaves com o segredo alterado: tem que ser recusada; as demais, aceitas
                        bool tampered = random.Next(4) == 0;
                        ok = validator.Validate(tampered ? tamperedKey : apiKey.Key) is null == tampered;
                        break;
                    case < 45:
                        // Identidades em rotação: parte vem do cache, parte é nova (expira em 30 s)
                        var result = await factory.CreateAsync(new ExternalIdentity
                        {
                            Scheme = "Test", Provider = "Test", UserId = $"usuario-{random.Next(20_000)}", Kind = PrincipalKind.User,
                            ExternalTenantId = "tid-contoso", Roles = ["leitor", $"grupo-{random.Next(10)}"], Scopes = ["api.read"]
                        });
                        ok = result.IsSuccess && new SecurityUser(result.Value).TenantId == "contoso";
                        break;
                    case < 65:
                        ok = registry.FindByExternalId("Test", $"tid-{random.Next(1_000)}") is { } tenant && tenant.Id.Length > 0;
                        break;
                    case < 66:
                        tenantMonitor.Set(Tenants(enabled: random.Next(2) == 0));
                        break;
                    case < 80:
                        using (context.RunAs(system))
                        {
                            await Task.Yield();
                            ok = user.Kind == PrincipalKind.System;
                        }
                        break;
                    case < 90:
                        ok = (await tokens.GetTokenAsync(scopeSet, stop.Token)).Token.Length > 0;
                        break;
                    default:
                        using (var request = new HttpRequestMessage(HttpMethod.Get, "https://api.contoso.com/pedidos"))
                        using (var response = await invoker.SendAsync(request, CancellationToken.None))
                            ok = response.IsSuccessStatusCode;
                        break;
                }

                if (!ok)
                    Interlocked.Increment(ref failures);
                Interlocked.Increment(ref operations);
            }
        }

        var watch = Stopwatch.StartNew();
        var workers = Enumerable.Range(0, Environment.ProcessorCount).Select(i => Task.Run(async () =>
        {
            try
            {
                await WorkerAsync(i);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
            }
        })).ToArray();
        var samples = new List<Sample>();
        while (!stop.IsCancellationRequested)
        {
            try { await Task.Delay(interval, stop.Token); }
            catch (OperationCanceledException) { break; }
            samples.Add(new Sample(watch.Elapsed.TotalSeconds, Interlocked.Read(ref operations), MemoryProbe.RetainedBytes(), MemoryProbe.HandleCount()));
        }
        await Task.WhenAll(workers);

        await Assert.That(samples.Count).IsGreaterThanOrEqualTo(8).Because("o soak precisa de amostras suficientes (aumente TEC_CARGA_SOAK_SEGUNDOS)");

        // Vazão de cada intervalo entre amostras
        var rates = samples.Select((s, i) => i == 0
            ? s.Operations / s.Seconds
            : (s.Operations - samples[i - 1].Operations) / (s.Seconds - samples[i - 1].Seconds)).ToArray();

        // Descarta o primeiro quarto (aquecimento: JIT, pools e caches) e compara o início com o fim da janela estável
        int skip = samples.Count / 4;
        int third = Math.Max((samples.Count - skip) / 3, 1);
        var first = samples.Skip(skip).Take(third).ToList();
        var last = samples.TakeLast(third).ToList();
        double firstThroughput = rates.Skip(skip).Take(third).Average();
        double lastThroughput = rates.TakeLast(third).Average();
        long firstMemory = Median(first.Select(s => s.RetainedBytes));
        long lastMemory = Median(last.Select(s => s.RetainedBytes));

        var report = new StringBuilder();
        report.AppendLine(CultureInfo.InvariantCulture, $"Duração: {duration.TotalSeconds:F0} s · workers: {Environment.ProcessorCount} · operações: {operations:N0} · falhas: {failures:N0} · tokens obtidos: {tokens.Calls:N0}");
        report.AppendLine("| t (s) | operações | memória retida | handles |");
        report.AppendLine("|---:|---:|---:|---:|");
        foreach (var s in samples)
            report.AppendLine(CultureInfo.InvariantCulture, $"| {s.Seconds:F0} | {s.Operations:N0} | {MemoryProbe.Megabytes(s.RetainedBytes)} | {s.Handles} |");
        report.AppendLine(CultureInfo.InvariantCulture, $"Vazão: {firstThroughput:N0} → {lastThroughput:N0} op/s · memória (mediana): {MemoryProbe.Megabytes(firstMemory)} → {MemoryProbe.Megabytes(lastMemory)}");
        LoadSettings.Report("Soak em processo (carga mista de segurança)", report.ToString());

        await Assert.That(Interlocked.Read(ref failures)).IsEqualTo(0).Because(report.ToString());
        await Assert.That(lastMemory - firstMemory).IsLessThan(Math.Max(16L * 1024 * 1024, firstMemory / 5)).Because(report.ToString());
        await Assert.That(last[^1].Handles - first[0].Handles).IsLessThan(200).Because(report.ToString());
        await Assert.That(lastThroughput).IsGreaterThan(firstThroughput * 0.6).Because(report.ToString());
    }

    // Mil tenants; "tid-0" alterna entre ativo e inativo a cada recarga (os demais continuam iguais)
    private static TenantOptions Tenants(bool enabled)
    {
        var options = new TenantOptions();
        for (int i = 0; i < 1_000; i++)
            options.Items[$"tenant-{i}"] = new TenantDefinition { Enabled = i != 0 || enabled, IdentityProviders = { ["Test"] = [$"tid-{i}"] } };
        return options;
    }

    private static long Median(IEnumerable<long> values)
    {
        var sorted = values.Order().ToArray();
        return sorted[sorted.Length / 2];
    }

    private sealed class OkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }
}
