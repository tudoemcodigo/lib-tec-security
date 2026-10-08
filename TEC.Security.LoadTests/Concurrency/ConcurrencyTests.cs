using System.Collections.Concurrent;
using System.Net;
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

namespace TEC.Security.LoadTests.Concurrency;

/// <summary>
/// Os tipos registrados como Singleton (validador de API key, fábrica de identidades, cadastro de tenants, cache de permissões,
/// provedor de token de serviço, contexto de segurança) são usados por muitas threads ao mesmo tempo: cada teste compara o
/// resultado concorrente com o resultado sequencial de referência. Em segurança, uma condição de corrida não é só um bug: é uma
/// identidade recebendo o tenant ou as permissões de outra.
/// </summary>
[Category(TestCategories.LoadCi)]
public class ConcurrencyTests
{
    private const int Workers = 64;

    // Registra a primeira divergência (para a mensagem) e conta todas
    private sealed class Divergences
    {
        private readonly ConcurrentQueue<string> _samples = new();
        private int _count;

        public int Count => _count;

        public void Add(string description)
        {
            if (Interlocked.Increment(ref _count) <= 5)
                _samples.Enqueue(description);
        }

        public override string ToString() => string.Join(Environment.NewLine, _samples);
    }

    [Test]
    public async Task ApiKeyValidator_ConcurrentValidation_MatchesSequentialResults()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero));
        var options = new ApiKeyOptions();
        var presented = new List<string>();
        for (int i = 0; i < 100; i++)
        {
            var key = ApiKeyGenerator.Generate($"sistema-{i:D3}");
            options.Keys[key.KeyId] = new ApiKeyDefinition
            {
                Hash = key.Hash,
                TenantId = $"tenant-{i % 7}",
                Permissions = [$"recurso-{i}:ler"],
                Enabled = i % 10 != 3,
                ExpiresOn = clock.GetUtcNow().AddDays(i % 10 == 5 ? -1 : 30)
            };
            presented.Add(key.Key);
            presented.Add(key.Key[..^2] + (key.Key[^2] == 'A' ? "BB" : "AA"));
        }

        presented.AddRange(["", "tec_", "tec_sistema-001_", "tec_SISTEMA-001_" + new string('A', 43), new string('x', 10_000), ApiKeyGenerator.Generate("nao-cadastrada").Key]);
        var validator = new ApiKeyValidator(new ManualOptionsMonitor<ApiKeyOptions>(options), clock);
        var expected = presented.Select(p => Describe(validator.Validate(p))).ToArray();

        var divergences = new Divergences();
        await Parallel.ForAsync(0, 200_000, new ParallelOptions { MaxDegreeOfParallelism = Workers }, (i, _) =>
        {
            int k = i % presented.Count;
            string actual = Describe(validator.Validate(presented[k]));
            if (actual != expected[k])
                divergences.Add($"chave {k}: esperado '{expected[k]}', obtido '{actual}'");
            return ValueTask.CompletedTask;
        });

        await Assert.That(expected.Count(e => e != "recusada")).IsEqualTo(80);
        await Assert.That(divergences.Count).IsEqualTo(0).Because(divergences.ToString());

        static string Describe(ExternalIdentity? identity) =>
            identity is null ? "recusada" : $"{identity.UserId}|{identity.TenantId}|{string.Join(',', identity.Permissions)}";
    }

    [Test]
    public async Task IdentityFactory_ConcurrentCreation_NoCrossContamination()
    {
        await using var provider = CreateServices(new Dictionary<string, string?>
        {
            ["Security:Tenants:contoso:IdentityProviders:Test:0"] = "tid-contoso",
            ["Security:Tenants:fabrikam:IdentityProviders:Test:0"] = "tid-fabrikam",
            ["Security:Tenants:inativo:Enabled"] = "false",
            ["Security:Tenants:inativo:IdentityProviders:Test:0"] = "tid-inativo",
        });
        var factory = provider.GetRequiredService<SecurityIdentityFactory>();
        string[] tids = ["tid-contoso", "tid-fabrikam", "tid-inativo", "tid-desconhecido"];

        var divergences = new Divergences();
        await Parallel.ForAsync(0, 20_000, new ParallelOptions { MaxDegreeOfParallelism = Workers }, async (i, ct) =>
        {
            string tid = tids[i % tids.Length];
            string userId = $"usuario-{i % 3_000}";
            string[] roles = [$"papel-{i % 5}", $"papel-{i % 11}"];

            var result = await factory.CreateAsync(new ExternalIdentity
            {
                Scheme = "Test",
                Provider = "Test",
                UserId = userId,
                Kind = PrincipalKind.User,
                ExternalTenantId = tid,
                Roles = roles,
                SourceClaims = [new System.Security.Claims.Claim("tec_perm", "admin:tudo")]
            }, ct);

            // Tenant inativo recusa; desconhecido fica sem tenant (RequireTenant = false)
            string? expectedTenant = tid switch { "tid-contoso" => "contoso", "tid-fabrikam" => "fabrikam", _ => null };
            if (tid == "tid-inativo")
            {
                if (result.IsSuccess)
                    divergences.Add($"{userId}: tenant inativo aceito");
                return;
            }

            if (result.IsFailure)
            {
                divergences.Add($"{userId}: recusado ({result.Error?.Code})");
                return;
            }

            var user = new SecurityUser(result.Value);
            var expectedPermissions = SimulatedDatabasePermissionStore.Expected(userId, roles).Concat(roles).ToHashSet(StringComparer.Ordinal);
            if (user.Id != userId || user.TenantId != expectedTenant || !user.Permissions.SetEquals(expectedPermissions) || user.HasPermission("admin:tudo"))
                divergences.Add($"{userId}/{tid}: obtido {user} com [{string.Join(',', user.Permissions.Order())}]");
        });

        await Assert.That(divergences.Count).IsEqualTo(0).Because(divergences.ToString());
    }

    [Test]
    public async Task PermissionCache_ConcurrentMisses_FewSourceQueries()
    {
        await using var provider = CreateServices(new Dictionary<string, string?>(), TimeSpan.FromMilliseconds(2));
        var factory = provider.GetRequiredService<SecurityIdentityFactory>();
        var store = provider.GetRequiredService<SimulatedDatabasePermissionStore>();
        const int identities = 300;
        const int requests = 30_000;

        var divergences = new Divergences();
        await Parallel.ForAsync(0, requests, new ParallelOptions { MaxDegreeOfParallelism = Workers }, async (i, ct) =>
        {
            string userId = $"usuario-{i % identities}";
            var result = await factory.CreateAsync(new ExternalIdentity
            {
                Scheme = "Test", Provider = "Test", UserId = userId, Kind = PrincipalKind.Application, Roles = ["leitor"]
            }, ct);
            if (result.IsFailure || !new SecurityUser(result.Value).HasPermission("leitor:executar"))
                divergences.Add($"{userId}: permissões do cache incorretas");
        });

        await Assert.That(divergences.Count).IsEqualTo(0).Because(divergences.ToString());
        // Uma única consulta por identidade ("single flight"): misses simultâneos da mesma identidade esperam a mesma consulta
        await Assert.That(store.Calls).IsEqualTo(identities);
    }

    [Test]
    public async Task TenantRegistry_ReadsDuringReloads_NeverSeeRejectedOrTornVersions()
    {
        static TenantOptions Version(bool alternativeEnabled, bool invalid)
        {
            var options = new TenantOptions();
            options.Items["fixo"] = new TenantDefinition { IdentityProviders = { ["Test"] = ["tid-fixo"] } };
            options.Items["alterna"] = new TenantDefinition { Enabled = alternativeEnabled, IdentityProviders = { ["Test"] = ["tid-alterna"] } };
            // Versão inválida: o mesmo id externo em dois tenants (recusada; a anterior continua valendo)
            if (invalid)
                options.Items["intruso"] = new TenantDefinition { IdentityProviders = { ["Test"] = ["tid-fixo"] } };
            return options;
        }

        var monitor = new ManualOptionsMonitor<TenantOptions>(Version(alternativeEnabled: true, invalid: false));
        using var registry = new ConfigurationTenantRegistry(monitor);
        using var stop = new CancellationTokenSource();
        long reads = 0;

        // Ao menos 2 mil recargas e até os leitores somarem 100 mil leituras (o pool de threads leva um tempo para subir)
        var writer = Task.Run(() =>
        {
            for (int i = 0; i < 2_000 || (Interlocked.Read(ref reads) < 100_000 && i < 1_000_000); i++)
                monitor.Set(Version(alternativeEnabled: i % 2 == 0, invalid: i % 7 == 0));
            stop.Cancel();
        });

        var divergences = new Divergences();
        var readers = Enumerable.Range(0, Workers / 2).Select(_ => Task.Run(() =>
        {
            while (!stop.IsCancellationRequested)
            {
                var fixedTenant = registry.FindByExternalId("test", "TID-FIXO");
                if (fixedTenant?.Id != "fixo")
                    divergences.Add($"tid-fixo resolvido para '{fixedTenant?.Id}'");
                if (registry.Find("intruso") is not null)
                    divergences.Add("versão inválida entrou em uso");
                if (registry.FindByExternalId("Test", "tid-alterna")?.Id is { } id && id != "alterna")
                    divergences.Add($"tid-alterna resolvido para '{id}'");
                Interlocked.Increment(ref reads);
            }
        })).ToArray();

        await Task.WhenAll([writer, .. readers]);

        await Assert.That(Interlocked.Read(ref reads)).IsGreaterThan(1_000);
        await Assert.That(divergences.Count).IsEqualTo(0).Because(divergences.ToString());
    }

    [Test]
    public async Task ServiceTokenProvider_SingleAcquisitionPerScopeSet_UnderContention()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var provider = new CountingTokenProvider(clock, TimeSpan.FromHours(1), TimeSpan.FromMilliseconds(30));
        string[][] scopeSets = [.. Enumerable.Range(0, 16).Select(i => new[] { $"api://servico-{i}/.default" })];

        async Task<int> BurstAsync()
        {
            var divergences = new Divergences();
            await Parallel.ForAsync(0, 20_000, new ParallelOptions { MaxDegreeOfParallelism = Workers }, async (i, ct) =>
            {
                var scopes = scopeSets[i % scopeSets.Length];
                var token = await provider.GetTokenAsync(scopes, ct);
                if (!token.Token.EndsWith(scopes[0], StringComparison.Ordinal))
                    divergences.Add($"token de outro escopo para {scopes[0]}: {token.Token}");
            });
            return divergences.Count;
        }

        int firstBurst = await BurstAsync();
        long afterFirst = provider.Calls;

        // Faltando menos de 5 minutos para expirar: todos renovam, ainda uma única vez por conjunto de escopos
        clock.Advance(TimeSpan.FromMinutes(56));
        int secondBurst = await BurstAsync();

        await Assert.That(firstBurst + secondBurst).IsEqualTo(0);
        await Assert.That(afterFirst).IsEqualTo(scopeSets.Length);
        await Assert.That(provider.Calls).IsEqualTo(scopeSets.Length * 2L);
    }

    [Test]
    public async Task AccessTokenHandler_ConcurrentRequests_TokenOnlyForAllowedHosts()
    {
        using var provider = new CountingTokenProvider(TimeProvider.System, TimeSpan.FromHours(1), TimeSpan.Zero);
        var options = new AccessTokenHandlerOptions { Scopes = { "api://contoso/.default" }, AllowedHosts = { "api.contoso.com" } };
        var sink = new RecordingHandler();
        using var invoker = new HttpMessageInvoker(new AccessTokenHandler(provider, options) { InnerHandler = sink });
        string[] urls =
        [
            "https://api.contoso.com/a", "https://API.CONTOSO.COM/b", "http://api.contoso.com/c", "https://api.contoso.com.atacante.test/d",
            "https://usuario@api.contoso.com/e", "https://atacante.test/api.contoso.com", "https://127.0.0.1/f",
        ];

        int blocked = 0;
        await Parallel.ForAsync(0, 20_000, new ParallelOptions { MaxDegreeOfParallelism = Workers }, async (i, ct) =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, urls[i % urls.Length]);
            try
            {
                using var response = await invoker.SendAsync(request, ct);
            }
            catch (HttpRequestException)
            {
                Interlocked.Increment(ref blocked);
            }
        });

        // Só os dois primeiros destinos (HTTPS no host permitido, sem usuário na URL) chegam ao handler interno, sempre com token
        await Assert.That(sink.Hosts.Keys.Order()).IsEquivalentTo(new[] { "api.contoso.com" });
        await Assert.That(sink.WithoutToken).IsEqualTo(0);
        await Assert.That(blocked).IsEqualTo(Enumerable.Range(0, 20_000).Count(i => i % urls.Length >= 2));
    }

    [Test]
    public async Task SecurityContext_ParallelRunAs_EachFlowSeesItsOwnIdentity()
    {
        await using var provider = CreateServices(new Dictionary<string, string?>
        {
            ["Security:Tenants:contoso:Enabled"] = "true",
        });
        var context = provider.GetRequiredService<ISecurityContext>();
        // Um único escopo compartilhado por todos os fluxos (ex.: worker que processa mensagens em paralelo)
        await using var scope = provider.CreateAsyncScope();
        var user = scope.ServiceProvider.GetRequiredService<ISecurityUser>();

        var principals = await Task.WhenAll(Enumerable.Range(0, Workers)
            .Select(i => context.CreateSystemPrincipalAsync($"servico-{i:D2}", i % 2 == 0 ? "contoso" : null)));
        await Assert.That(principals.All(p => p.IsSuccess)).IsTrue();

        var divergences = new Divergences();
        await Task.WhenAll(Enumerable.Range(0, Workers).Select(i => Task.Run(async () =>
        {
            using (context.RunAs(principals[i].Value))
            {
                for (int step = 0; step < 500; step++)
                {
                    await Task.Yield();
                    if (user.Id != $"system:servico-{i:D2}" || user.TenantId != (i % 2 == 0 ? "contoso" : null) || user.Kind != PrincipalKind.System)
                        divergences.Add($"fluxo {i}, passo {step}: viu {user}");
                }
            }

            if (user.IsAuthenticated)
                divergences.Add($"fluxo {i}: identidade continuou valendo depois do escopo");
        })));

        await Assert.That(divergences.Count).IsEqualTo(0).Because(divergences.ToString());
    }

    private static ServiceProvider CreateServices(Dictionary<string, string?> settings, TimeSpan? storeLatency = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        var services = new ServiceCollection();
        services.AddSingleton(new PermissionStoreLatency(storeLatency ?? TimeSpan.Zero));
        services.AddTecSecurity(configuration, security => security.UsePermissionStore<SimulatedDatabasePermissionStore>());
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public ConcurrentDictionary<string, int> Hosts { get; } = new(StringComparer.Ordinal);

        public int WithoutToken;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Hosts.AddOrUpdate(request.RequestUri!.IdnHost, 1, (_, n) => n + 1);
            if (request.Headers.Authorization?.Scheme != "Bearer")
                Interlocked.Increment(ref WithoutToken);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
