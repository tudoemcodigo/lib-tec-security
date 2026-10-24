using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using TEC.Core.Security;
using TEC.Security.ApiKeys;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Permissions;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests.Security.Adversarial;

/// <summary>
/// Negação de serviço: credenciais adversariais (headers gigantes, tokens inflados, JSON aninhado, milhares de claims, chaves
/// desconhecidas em massa) precisam ser recusadas rápido, sem processar a entrada inteira e sem derrubar a requisição (5xx).
/// </summary>
/// <remarks>
/// Os limites de tempo são folgados (máquinas de CI lentas): pegam laços sem fim e crescimento quadrático/exponencial,
/// não pequenas regressões de desempenho (essas ficam com o TEC.Security.Benchmarks). A classe roda com exclusividade
/// ([NotInParallel] sem chave): mede tempo de parede, e a suíte inteira em paralelo num runner de 2 vCPUs estoura os
/// limites sem regressão nenhuma.
/// </remarks>
[NotInParallel]
public class DosResistanceTests
{
    private static readonly TimeSpan Fast = TimeSpan.FromSeconds(5);

    // ---------- HTTP: entradas gigantes param nos limites ----------

    [Test]
    [Arguments("authorization-1mb")]
    [Arguments("bearer-1mb")]
    [Arguments("api-key-1mb")]
    [Arguments("hub-query-60kb")]   // abaixo do limite de tamanho de Uri do .NET 8 (65 519) e bem acima do MaxTokenLength
    [Arguments("api-key-1000-headers")]
    [Arguments("authorization-1000-headers")]
    public async Task Http_GiantOrRepeatedCredentials_Rejected401Fast(string scenario)
    {
        await using var app = await SecuredTestApp.StartAsync();
        string mega = new('A', 1024 * 1024);

        using var request = new HttpRequestMessage(HttpMethod.Get, scenario == "hub-query-60kb" ? "/hubs/chat/negotiate?access_token=" + mega[..60_000] : "/pedidos");
        switch (scenario)
        {
            case "authorization-1mb": request.Headers.TryAddWithoutValidation("Authorization", mega); break;
            case "bearer-1mb": request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + mega); break;
            case "api-key-1mb": request.Headers.TryAddWithoutValidation("X-Api-Key", "tec_erp-contoso_" + mega); break;
            case "api-key-1000-headers": request.Headers.TryAddWithoutValidation("X-Api-Key", Enumerable.Repeat(app.ApiKey.Key, 1000)); break;
            case "authorization-1000-headers": request.Headers.TryAddWithoutValidation("Authorization", Enumerable.Repeat("Bearer " + app.ValidToken(), 1000)); break;
        }

        var watch = Stopwatch.StartNew();
        using var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized).Because(scenario);
        await Assert.That(watch.Elapsed).IsLessThan(Fast);
    }

    [Test]
    public async Task Http_TokenWithThousandsOfRoles_WithinMaxLength_RejectedAsInflated()
    {
        // Token assinado e válido, mas com papéis acima do limite por identidade (token inflado): recusado, não truncado
        await using var app = await SecuredTestApp.StartAsync(o => o.MaxTokenLength = 256 * 1024);
        string token = app.ValidToken(t => t.Roles.AddRange(Enumerable.Range(0, 10_000).Select(i => $"r{i}")));

        var watch = Stopwatch.StartNew();
        using var response = await app.Client.SendAsync(Get("/pedidos", token));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(watch.Elapsed).IsLessThan(Fast);
        await Assert.That(app.App.Logs.All).Contains("quantidade de papéis acima do limite");
    }

    [Test]
    [Arguments(64)]
    [Arguments(5_000)]
    public async Task Http_DeeplyNestedJsonInToken_Rejected401_NoServerError(int depth)
    {
        await using var app = await SecuredTestApp.StartAsync(o => o.MaxTokenLength = 256 * 1024);
        string nested = string.Concat(Enumerable.Repeat("{\"a\":", depth)) + "1" + new string('}', depth);
        string payload = $$"""{"iss":"{{app.Issuer.Issuer}}","aud":"{{app.Issuer.Audience}}","sub":"x","exp":{{DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds()}},"n":{{nested}}}""";
        string header = app.ValidToken().Split('.')[0];
        string token = $"{header}.{Base64Url(payload)}.{app.ValidToken().Split('.')[2]}";

        var watch = Stopwatch.StartNew();
        using var response = await app.Client.SendAsync(Get("/pedidos", token));

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(watch.Elapsed).IsLessThan(Fast);
    }

    [Test]
    public async Task Http_FloodOfTokensFromUnknownKeys_StaysFastAndRejected()
    {
        // Cada token com um kid desconhecido: a validação não pode virar uma busca de chaves por requisição
        await using var app = await SecuredTestApp.StartAsync();
        string payload = app.ValidToken().Split('.')[1];
        var tokens = Enumerable.Range(0, 500).Select(_ =>
        {
            string header = Base64Url($$"""{"alg":"RS256","kid":"{{Guid.NewGuid():N}}","typ":"JWT"}""");
            return $"{header}.{payload}.{Convert.ToBase64String(RandomNumberGenerator.GetBytes(256)).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
        }).ToArray();

        var watch = Stopwatch.StartNew();
        var responses = await Task.WhenAll(tokens.Select(async token =>
        {
            using var response = await app.Client.SendAsync(Get("/pedidos", token));
            return response.StatusCode;
        }));

        await Assert.That(responses.All(s => s == HttpStatusCode.Unauthorized)).IsTrue();
        await Assert.That(watch.Elapsed).IsLessThan(TimeSpan.FromSeconds(15));
    }

    // ---------- Núcleo: validação em tempo linear e limites antes do trabalho ----------

    [Test]
    public async Task SecurityRules_HugeHostileInputs_LinearTime()
    {
        string[] inputs =
        [
            new string('a', 2_000_000),
            new string('a', 2_000_000) + "\n",
            string.Concat(Enumerable.Repeat("a:", 1_000_000)) + " ",
            new string('-', 2_000_000),
            string.Concat(Enumerable.Repeat("x\u0000", 1_000_000)),
        ];

        var watch = Stopwatch.StartNew();
        foreach (string input in inputs)
        {
            _ = SecurityRules.IsValidName(input);
            _ = SecurityRules.IsValidTenantId(input);
            _ = SecurityRules.IsValidServiceName(input);
            _ = SecurityRules.IsValidUserId(input);
            _ = SecurityRules.SanitizeDisplayName(input);
            _ = ApiKeyGenerator.DecodeHash(input);
        }

        await Assert.That(watch.Elapsed).IsLessThan(Fast);
    }

    [Test]
    public async Task IdentityFactory_MillionRoles_RejectedWithoutProcessingAll()
    {
        var factory = new SecurityIdentityFactory(new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions())),
            new FakePermissionStore(), new TestOptionsMonitor<SecurityOptions>(new SecurityOptions()));
        long enumerated = 0;
        // Enumerável preguiçoso: conta quantos papéis a fábrica realmente leu antes de recusar
        IEnumerable<string> Roles()
        {
            for (int i = 0; i < 1_000_000; i++)
            {
                enumerated++;
                yield return $"papel:{i}";
            }
        }

        var watch = Stopwatch.StartNew();
        var result = await factory.CreateAsync(new ExternalIdentity
        {
            Scheme = "Test", Provider = "Test", UserId = "u", Kind = PrincipalKind.User, Roles = new LazyCollection(Roles(), 1_000_000)
        });

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(enumerated).IsLessThanOrEqualTo(SecurityRules.MaxItemsPerIdentity + 1);
        await Assert.That(watch.Elapsed).IsLessThan(Fast);
    }

    [Test]
    public async Task ApiKeyValidator_HugeOrAbsurdInputs_RejectedWithoutHashingThem()
    {
        var options = new ApiKeyOptions();
        var key = ApiKeyGenerator.Generate("erp-contoso");
        options.Keys[key.KeyId] = new ApiKeyDefinition { Hash = key.Hash, ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) };
        var validator = new ApiKeyValidator(new TestOptionsMonitor<ApiKeyOptions>(options));
        string[] inputs = [new string('a', 5_000_000), "tec_erp-contoso_" + new string('A', 5_000_000), "tec_" + new string('_', 5_000_000)];

        var watch = Stopwatch.StartNew();
        foreach (string input in inputs)
        {
            for (int i = 0; i < 1_000; i++)
                _ = validator.Validate(input);
        }

        // 3 mil validações de 10 MB: só é rápido se o tamanho for recusado antes de qualquer trabalho proporcional à entrada
        await Assert.That(watch.Elapsed).IsLessThan(Fast);
        await Assert.That(inputs.All(i => validator.Validate(i) is null)).IsTrue();
    }

    [Test]
    public async Task PermissionCache_DistinctIdentitiesBeyondLimit_FailsNothing()
    {
        // Mais identidades distintas que o limite do cache (50 mil): o cache descarta, mas nenhuma consulta falha
        var store = new FakePermissionStore { Resolve = c => [$"{c.UserId}:ler"] };
        using var cache = new CachingPermissionStore(store, TimeSpan.FromMinutes(5));
        int wrong = 0;

        await Parallel.ForAsync(0, 60_000, async (i, ct) =>
        {
            var permissions = await cache.GetPermissionsAsync(new Abstractions.PermissionContext("Test", "Test", $"u{i}", null, PrincipalKind.User, []), ct);
            if (permissions.Single() != $"u{i}:ler")
                Interlocked.Increment(ref wrong);
        });

        await Assert.That(wrong).IsEqualTo(0);
        await Assert.That(store.Calls).IsEqualTo(60_000);
    }

    private static HttpRequestMessage Get(string path, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private static string Base64Url(string json) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Coleção com <c>Count</c> declarado, enumerada sob demanda.</summary>
    private sealed class LazyCollection(IEnumerable<string> items, int count) : IReadOnlyCollection<string>
    {
        public int Count => count;

        public IEnumerator<string> GetEnumerator() => items.GetEnumerator();

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
    }
}
