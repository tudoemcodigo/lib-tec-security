using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using TEC.Core.Common.Results;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Permissions;
using TEC.Security.Tenants;
using TEC.Security.Tokens;

namespace TEC.Security.Benchmarks;

/// <summary>
/// API key: geração e validação. Todos os caminhos de recusa (id desconhecido, segredo errado) devem custar o mesmo que o
/// de aceite: o tempo de resposta não pode revelar quais ids existem.
/// </summary>
[MemoryDiagnoser]
public class ApiKeyBenchmarks
{
    private ApiKeyValidator _validator = null!;
    private string _valid = string.Empty;
    private string _wrongSecret = string.Empty;
    private string _unknownId = string.Empty;

    [Params(1, 1_000)]
    public int Keys { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var options = new ApiKeyOptions();
        for (int i = 0; i < Keys; i++)
        {
            var key = ApiKeyGenerator.Generate($"sistema-{i:D4}");
            options.Keys[key.KeyId] = new ApiKeyDefinition { Hash = key.Hash, ExpiresOn = DateTimeOffset.UtcNow.AddYears(1), Permissions = ["pedidos:ler"] };
            if (i == 0)
                _valid = key.Key;
        }

        _validator = new ApiKeyValidator(new StaticOptionsMonitor<ApiKeyOptions>(options));
        _wrongSecret = _valid[..^1] + (_valid[^1] == 'A' ? 'B' : 'A');
        _unknownId = ApiKeyGenerator.Generate("id-inexistente").Key;
    }

    [Benchmark]
    public GeneratedApiKey Generate() => ApiKeyGenerator.Generate("erp-contoso");

    [Benchmark(Baseline = true)]
    public ExternalIdentity? ValidateAccepted() => _validator.Validate(_valid);

    [Benchmark]
    public ExternalIdentity? ValidateWrongSecret() => _validator.Validate(_wrongSecret);

    [Benchmark]
    public ExternalIdentity? ValidateUnknownId() => _validator.Validate(_unknownId);

    [Benchmark]
    public ExternalIdentity? ValidateMalformed() => _validator.Validate("Bearer qualquer-coisa");
}

/// <summary>
/// Normalização da identidade (executada em toda requisição autenticada): tenant pelo cadastro, papéis e permissões validados.
/// </summary>
[MemoryDiagnoser]
public class IdentityBenchmarks
{
    private const string Tid = "11111111-1111-1111-1111-111111111111";

    private SecurityIdentityFactory _factory = null!;
    private ExternalIdentity _typical = null!;
    private ExternalIdentity _inflated = null!;
    private ClaimsPrincipal _principal = null!;

    [GlobalSetup]
    public void Setup()
    {
        var tenants = new TenantOptions();
        tenants.Items["contoso"] = new TenantDefinition { IdentityProviders = { ["EntraId"] = [Tid] } };
        var permissions = new PermissionOptions { Roles = { ["Gerente"] = ["pedidos:ler", "pedidos:criar", "pedidos:cancelar"] } };

        _factory = new SecurityIdentityFactory(
            new ConfigurationTenantRegistry(new StaticOptionsMonitor<TenantOptions>(tenants)),
            new ConfigurationPermissionStore(new StaticOptionsMonitor<PermissionOptions>(permissions)),
            new StaticOptionsMonitor<SecurityOptions>(new SecurityOptions { RequireTenant = true }));

        _typical = new ExternalIdentity
        {
            Scheme = "Funcionarios",
            Provider = "EntraId",
            UserId = Guid.NewGuid().ToString("D"),
            Kind = PrincipalKind.User,
            ExternalTenantId = Tid,
            Name = "Maria da Silva",
            Roles = ["Gerente", "Vendedor"],
            Scopes = ["access_as_user"],
            SourceClaims = [new Claim("oid", "x"), new Claim("tid", Tid), new Claim("tec_perm", "injetado")]
        };

        // Perto do limite de itens por identidade (token inflado, mas ainda aceito)
        _inflated = new ExternalIdentity
        {
            Scheme = _typical.Scheme,
            Provider = _typical.Provider,
            UserId = _typical.UserId,
            Kind = PrincipalKind.User,
            ExternalTenantId = Tid,
            Roles = [.. Enumerable.Range(0, SecurityRules.MaxItemsPerIdentity / 2).Select(i => $"papel:{i}")],
            Scopes = [.. Enumerable.Range(0, SecurityRules.MaxItemsPerIdentity / 2).Select(i => $"escopo.{i}")]
        };

        _principal = _factory.CreateAsync(_typical).GetAwaiter().GetResult().Value;
    }

    [Benchmark(Baseline = true)]
    public Task<Result<ClaimsPrincipal>> CreateTypical() => _factory.CreateAsync(_typical);

    [Benchmark]
    public Task<Result<ClaimsPrincipal>> CreateInflated() => _factory.CreateAsync(_inflated);

    [Benchmark]
    public Task<Result<ClaimsPrincipal>> Revalidate() => _factory.RevalidateAsync(_principal);

    [Benchmark]
    public bool ReadSecurityUser() => new SecurityUser(_principal).HasPermission("pedidos:cancelar");
}

/// <summary>Cadastro de tenants: consultas (toda requisição) e montagem do snapshot (inicialização e cada recarga).</summary>
[MemoryDiagnoser]
public class TenantBenchmarks
{
    private ConfigurationTenantRegistry _registry = null!;
    private StaticOptionsMonitor<TenantOptions> _options = null!;
    private string _existing = string.Empty;

    [Params(10, 10_000)]
    public int Tenants { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        var options = new TenantOptions();
        for (int i = 0; i < Tenants; i++)
            options.Items[$"tenant-{i}"] = new TenantDefinition { IdentityProviders = { ["EntraId"] = [Guid.NewGuid().ToString("D")] } };

        _options = new StaticOptionsMonitor<TenantOptions>(options);
        _registry = new ConfigurationTenantRegistry(_options);
        _existing = options.Items[$"tenant-{Tenants / 2}"].IdentityProviders["EntraId"][0].ToUpperInvariant();
    }

    [GlobalCleanup]
    public void Cleanup() => _registry.Dispose();

    [Benchmark(Baseline = true)]
    public TenantInfo? FindByExternalId() => _registry.FindByExternalId("EntraId", _existing);

    [Benchmark]
    public TenantInfo? FindByExternalIdMiss() => _registry.FindByExternalId("EntraId", "00000000-0000-0000-0000-000000000000");

    [Benchmark]
    public TenantInfo? Find() => _registry.Find("tenant-1");

    [Benchmark]
    public int Build()
    {
        using var registry = new ConfigurationTenantRegistry(_options);
        return registry.GetEnabledExternalIds("EntraId").Count;
    }
}

/// <summary>Token de serviço: cache do provedor e conferência do destino antes de anexar o token.</summary>
[MemoryDiagnoser]
public class ServiceTokenBenchmarks
{
    private static readonly string[] Scopes = ["api://contoso-api/.default"];

    private FixedTokenProvider _provider = null!;
    private AccessTokenHandlerOptions _options = null!;
    private HttpMessageInvoker _invoker = null!;
    private readonly Uri _allowed = new("https://api.contoso.com/pedidos?id=1");
    private readonly Uri _ssrf = new("https://api.contoso.com.atacante.test/pedidos");

    [GlobalSetup]
    public void Setup()
    {
        _provider = new FixedTokenProvider();
        _options = new AccessTokenHandlerOptions { Scopes = { Scopes[0] }, AllowedHosts = { "api.contoso.com" } };
        _invoker = new HttpMessageInvoker(new AccessTokenHandler(_provider, _options) { InnerHandler = new OkHandler() });
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _invoker.Dispose();
        _provider.Dispose();
    }

    [Benchmark(Baseline = true)]
    public ValueTask<AccessToken> CachedToken() => _provider.GetTokenAsync(Scopes, CancellationToken.None);

    [Benchmark]
    public bool AllowedDestination() => _options.IsAllowedDestination(_allowed);

    [Benchmark]
    public bool BlockedDestination() => _options.IsAllowedDestination(_ssrf);

    [Benchmark]
    public async Task<int> HandlerSend()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, _allowed);
        using var response = await _invoker.SendAsync(request, CancellationToken.None);
        return (int)response.StatusCode;
    }

    private sealed class FixedTokenProvider() : CachingAccessTokenProvider("Bench")
    {
        protected override ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new AccessToken("token-de-servico", DateTimeOffset.UtcNow.AddHours(1)));
    }

    private sealed class OkHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
    }
}

/// <summary>Validação dos formatos aceitos (papel, permissão, tenant, id), executada para cada valor de cada identidade.</summary>
[MemoryDiagnoser]
public class RulesBenchmarks
{
    private readonly string _name = "clientes:escrever";
    private readonly string _longName = new('a', SecurityRules.MaxNameLength);
    private readonly string _hostile = new string('a', SecurityRules.MaxNameLength * 64) + "!";
    private readonly string _userId = Guid.NewGuid().ToString("D");

    [Benchmark(Baseline = true)]
    public bool ValidName() => SecurityRules.IsValidName(_name);

    [Benchmark]
    public bool LongName() => SecurityRules.IsValidName(_longName);

    [Benchmark]
    public bool HostileName() => SecurityRules.IsValidName(_hostile);

    [Benchmark]
    public bool UserId() => SecurityRules.IsValidUserId(_userId);

    [Benchmark]
    public string? DisplayName() => SecurityRules.SanitizeDisplayName("  Maria da Silva  ");
}
