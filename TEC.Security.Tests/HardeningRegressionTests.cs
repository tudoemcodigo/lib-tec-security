using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TEC.Core.Exceptions;
using TEC.Core.Security;
using Base64UrlEncoder = TEC.Core.Text.Codecs.Base64UrlEncoder;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.EntraId.Internal;
using TEC.Security.Permissions;
using TEC.Security.Testing;
using TEC.Security.Tokens;

namespace TEC.Security.Tests;

/// <summary>
/// Regressões da revisão de segurança e escala: cada teste falharia na versão anterior do código (ver o comentário de cada um).
/// </summary>
public class HardeningRegressionTests
{
    // ================================================================ API keys

    [Test]
    public async Task Non_canonical_hash_in_the_catalog_is_rejected()
    {
        // Antes: a decodificação aceitava bits finais diferentes de zero (duas grafias para o mesmo hash)
        string hash = ApiKeyGenerator.Generate("erp-contoso").Hash;
        char last = hash[^1];
        string nonCanonical = hash[..^1] + Base64UrlAlphabet[Base64UrlAlphabet.IndexOf(last, StringComparison.Ordinal) | 1];

        await Assert.That(ApiKeyGenerator.DecodeHash(hash)).IsNotNull();
        await Assert.That(ApiKeyGenerator.DecodeHash(nonCanonical)).IsNull();
        await Assert.That(new ApiKeyOptionsValidator().Validate(null, Catalog(nonCanonical)).Failed).IsTrue();
    }

    [Test]
    public async Task Generated_key_and_hash_use_the_core_Base64Url_encoder()
    {
        var key = ApiKeyGenerator.Generate("erp-contoso");
        string secret = key.Key[(ApiKeyGenerator.Prefix.Length + "erp-contoso_".Length)..];

        await Assert.That(Base64UrlEncoder.IsValid(secret)).IsTrue();
        await Assert.That(Base64UrlEncoder.TryDecode(secret, out byte[] bytes) && bytes.Length == ApiKeyGenerator.SecretBytes).IsTrue();
        await Assert.That(key.Hash).IsEqualTo(Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(secret))));
    }

    [Test]
    public async Task Invalid_api_key_configuration_is_not_reevaluated_on_every_request()
    {
        // Antes: cada requisição relia as opções inválidas e lançava OptionsValidationException (caro sob carga)
        var monitor = new ThrowingOptionsMonitor<ApiKeyOptions>();
        var validator = new ApiKeyValidator(monitor);

        for (int i = 0; i < 1000; i++)
            _ = validator.Validate("tec_erp-contoso_" + new string('A', 43));

        await Assert.That(monitor.Reads).IsLessThanOrEqualTo(5);
    }

    // ================================================================ nome de exibição

    [Test]
    public async Task Display_name_with_bidi_override_or_line_separator_is_rejected()
    {
        // Antes: só caracteres de controle (Cc) eram recusados; U+202E inverte o texto exibido e U+2028 quebra linha em logs
        await Assert.That(SecurityRules.SanitizeDisplayName("fatura" + (char)0x202E + "fdp.exe")).IsNull();
        await Assert.That(SecurityRules.SanitizeDisplayName("linha1" + (char)0x2028 + "linha2")).IsNull();
        await Assert.That(SecurityRules.SanitizeDisplayName("x" + (char)0x2066 + "y")).IsNull();
        await Assert.That(SecurityRules.SanitizeDisplayName("solto" + (char)0xD83D)).IsNull();
        await Assert.That(SecurityRules.SanitizeDisplayName("  Maria da Silva  ")).IsEqualTo("Maria da Silva");
    }

    [Test]
    public async Task Display_name_truncation_never_splits_a_surrogate_pair()
    {
        // Antes: o corte em 256 caracteres podia deixar meio emoji (surrogate alto solto) no fim do nome
        string emoji = char.ConvertFromUtf32(0x1F600);
        string name = new string('a', SecurityRules.MaxDisplayNameLength - 1) + emoji + "zzz";

        string? sanitized = SecurityRules.SanitizeDisplayName(name);

        await Assert.That(sanitized).IsNotNull();
        await Assert.That(sanitized!.Length).IsLessThanOrEqualTo(SecurityRules.MaxDisplayNameLength);
        await Assert.That(char.IsHighSurrogate(sanitized[^1])).IsFalse();
    }

    // ================================================================ cache de permissões

    [Test]
    public async Task Concurrent_cache_misses_for_the_same_identity_query_the_store_once()
    {
        // Antes: sem "uma carga por chave", N requisições simultâneas da mesma identidade faziam N consultas ao banco
        var store = new SlowPermissionStore(TimeSpan.FromMilliseconds(200));
        using var cache = new CachingPermissionStore(store, TimeSpan.FromMinutes(5));
        var context = Context("user-1", "Gerente");

        var results = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => cache.GetPermissionsAsync(context, default).AsTask()));

        await Assert.That(store.Calls).IsEqualTo(1);
        await Assert.That(results.All(r => r.Contains("pedidos:ler"))).IsTrue();
    }

    [Test]
    public async Task Cancellation_of_the_first_caller_does_not_fail_the_other_waiters()
    {
        var store = new SlowPermissionStore(TimeSpan.FromMilliseconds(300));
        using var cache = new CachingPermissionStore(store, TimeSpan.FromMinutes(5));
        var context = Context("user-2", "Gerente");
        using var cancel = new CancellationTokenSource();

        var first = cache.GetPermissionsAsync(context, cancel.Token).AsTask();
        await Task.Delay(50);
        var second = cache.GetPermissionsAsync(context, CancellationToken.None).AsTask();
        await cancel.CancelAsync();

        await Assert.That(async () => await first).Throws<OperationCanceledException>();
        await Assert.That((await second).Contains("pedidos:ler")).IsTrue();
    }

    [Test]
    public async Task Permission_cache_key_has_fixed_size_even_with_many_roles()
    {
        // Antes: a chave concatenava todos os papéis (até 512 x 128 caracteres por entrada, 50 mil entradas)
        var roles = Enumerable.Range(0, SecurityRules.MaxItemsPerIdentity).Select(i => $"papel-{i}-{new string('x', 100)}").ToArray();

        string key = CachingPermissionStore.CreateKey(Context("user-3", roles));

        await Assert.That(key.Length).IsEqualTo(43);
    }

    [Test]
    public async Task Null_result_from_the_store_is_an_empty_permission_set()
    {
        // Antes: [.. null] lançava NullReferenceException dentro do cache (autenticação recusada por erro interno)
        using var cache = new CachingPermissionStore(new NullPermissionStore(), TimeSpan.FromMinutes(5));

        var permissions = await cache.GetPermissionsAsync(Context("user-4", "Gerente"), default);

        await Assert.That(permissions.Count).IsEqualTo(0);
    }

    // ================================================================ contexto de segurança

    [Test]
    public async Task RunAs_in_one_container_is_not_visible_in_another_container()
    {
        // Antes: o AsyncLocal era estático, compartilhado por todos os containers do processo
        using var first = BuildProvider();
        using var second = BuildProvider();
        var firstContext = first.GetRequiredService<ISecurityContext>();
        var principal = (await firstContext.CreateSystemPrincipalAsync("fechamento-mensal")).Value;

        using (firstContext.RunAs(principal))
        {
            await Assert.That(firstContext.Current).IsNotNull();
            await Assert.That(second.GetRequiredService<ISecurityContext>().Current).IsNull();
        }
    }

    [Test]
    public async Task Registering_two_permission_stores_or_tenant_registries_fails_explicitly()
    {
        // Antes: a segunda chamada substituía a primeira em silêncio
        await Assert.That(() => BuildProvider(b => b.UsePermissionStore<NullPermissionStore>().UsePermissionStore<NullPermissionStore>()))
            .Throws<InvalidOperationException>();
        await Assert.That(() => BuildProvider(b => b.UseTenantRegistry<EmptyTenantRegistry>().UseTenantRegistry<EmptyTenantRegistry>()))
            .Throws<InvalidOperationException>();
    }

    // ================================================================ tokens de serviço

    [Test]
    public async Task Refresh_failure_keeps_using_the_current_token_while_it_is_still_valid()
    {
        // Antes: uma falha passageira do provedor na janela de renovação derrubava as chamadas, mesmo com token válido
        var time = new FixedTimeProvider(DateTimeOffset.UtcNow);
        using var provider = new FlakyTokenProvider(time, TimeSpan.FromHours(1));
        string[] scopes = ["api://estoque/.default"];

        var first = await provider.GetTokenAsync(scopes, default);
        provider.Fail = true;
        time.Now = time.Now.AddMinutes(57);
        var stillValid = await provider.GetTokenAsync(scopes, default);
        time.Now = time.Now.AddMinutes(3);

        await Assert.That(stillValid.Token).IsEqualTo(first.Token);
        var thrown = await Assert.That(async () => await provider.GetTokenAsync(scopes, default)).ThrowsExactly<SecurityTokenAcquisitionException>();
        await Assert.That(thrown!.Code).IsEqualTo(SecurityErrors.ProviderFailureCode);
        await Assert.That(thrown.StatusCode).IsEqualTo(502);
        await Assert.That(thrown is AppException).IsTrue();
    }

    [Test]
    public async Task Disposed_token_provider_throws_ObjectDisposedException()
    {
        var provider = new FlakyTokenProvider(new FixedTimeProvider(DateTimeOffset.UtcNow), TimeSpan.FromHours(1));
        provider.Dispose();

        await Assert.That(async () => await provider.GetTokenAsync(["x/.default"], default)).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Token_provider_limits_the_number_of_distinct_scope_sets()
    {
        // Antes: cada conjunto de escopos diferente criava uma entrada (e um SemaphoreSlim) para sempre
        using var provider = new FlakyTokenProvider(new FixedTimeProvider(DateTimeOffset.UtcNow), TimeSpan.FromHours(1));
        for (int i = 0; i < CachingAccessTokenProvider.MaxScopeSets; i++)
            await provider.GetTokenAsync([$"api://s{i}/.default"], default);

        await Assert.That(async () => await provider.GetTokenAsync(["api://extra/.default"], default)).Throws<InvalidOperationException>();
        await Assert.That((await provider.GetTokenAsync(["api://s0/.default"], default)).Token).IsNotNull();
    }

    // ================================================================ JWT e OIDC

    [Test]
    [Arguments(SecurityAlgorithms.HmacSha256Signature)]
    [Arguments(SecurityAlgorithms.HmacSha512Signature)]
    [Arguments("hs256")]
    [Arguments("none")]
    [Arguments("RS1")]
    [Arguments("")]
    public async Task Jwt_enforcement_rejects_HMAC_in_any_spelling_and_unknown_algorithms(string algorithm)
    {
        // Antes: só nomes começando com "HS" eram recusados; o URI ...#hmac-sha256 passava
        var options = HardenedBearerOptions();
        options.TokenValidationParameters.ValidAlgorithms = [algorithm];

        await Assert.That(() => JwtHardening.Enforce(options, "Teste")).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Jwt_enforcement_accepts_asymmetric_algorithms_and_rejects_custom_algorithm_validator()
    {
        var options = HardenedBearerOptions();
        options.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.EcdsaSha384];
        JwtHardening.Enforce(options, "Teste");

        options.TokenValidationParameters.AlgorithmValidator = (_, _, _, _) => true;
        await Assert.That(() => JwtHardening.Enforce(options, "Teste")).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Oidc_enforcement_rejects_HMAC_uri_and_saved_tokens()
    {
        var options = HardenedOidcOptions();
        SecurityBuilderWebLoginExtensions.EnforceOidc(options, "Web.oidc");

        options.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.HmacSha256Signature];
        await Assert.That(() => SecurityBuilderWebLoginExtensions.EnforceOidc(options, "Web.oidc")).Throws<InvalidOperationException>();

        options = HardenedOidcOptions();
        options.SaveTokens = true;
        await Assert.That(() => SecurityBuilderWebLoginExtensions.EnforceOidc(options, "Web.oidc")).Throws<InvalidOperationException>();
    }

    // ================================================================ Entra ID

    [Test]
    public async Task Token_endpoint_response_without_length_is_read_with_a_ceiling()
    {
        // Antes: sem Content-Length (resposta em partes) o corpo era lido inteiro, sem limite
        using var http = new HttpClient(new StaticHandler(() => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new UnknownLengthContent(EntraIdTokenEndpoint.MaxResponseBytes + 1024)
        }));
        var endpoint = new EntraIdTokenEndpoint(http, TimeProvider.System);

        await Assert.That(async () => await endpoint.OnBehalfOfAsync("https://login.microsoftonline.com/t/oauth2/v2.0/token", "c",
            new ClientAuthentication("s", null), "user-token", ["x/.default"], default)).Throws<HttpRequestException>();
    }

    [Test]
    public async Task Token_endpoint_expiration_uses_the_injected_clock_and_rejects_absurd_values()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        var token = EntraIdTokenEndpoint.Parse("""{"access_token":"abc","expires_in":"3600"}"""u8.ToArray(), true, 200, now);

        await Assert.That(token.ExpiresOn).IsEqualTo(now.AddHours(1));
        await Assert.That(() => EntraIdTokenEndpoint.Parse("""{"access_token":"abc","expires_in":99999999999}"""u8.ToArray(), true, 200, now))
            .Throws<HttpRequestException>();
        await Assert.That(() => EntraIdTokenEndpoint.Parse("""{"access_token":"abc","expires_in":1.5}"""u8.ToArray(), true, 200, now))
            .Throws<HttpRequestException>();
        await Assert.That(() => EntraIdTokenEndpoint.Parse("<html>erro</html>"u8.ToArray(), false, 502, now))
            .Throws<HttpRequestException>();
    }

    [Test]
    public async Task Federated_token_file_is_read_with_a_size_limit()
    {
        // Antes: File.ReadAllTextAsync lia o arquivo inteiro antes de conferir o tamanho
        string directory = Path.Combine(Path.GetTempPath(), "tec-security-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            string small = Path.Combine(directory, "token");
            await File.WriteAllTextAsync(small, "  eyJ.token.assinado \n");
            string big = Path.Combine(directory, "big");
            await File.WriteAllTextAsync(big, new string('a', EntraIdClientCredential.MaxFederatedTokenBytes + 1));
            string invalid = Path.Combine(directory, "invalid");
            await File.WriteAllBytesAsync(invalid, [0xC3, 0x28]);

            await Assert.That(EntraIdClientCredential.ReadFederatedToken(small)).IsEqualTo("eyJ.token.assinado");
            await Assert.That(() => EntraIdClientCredential.ReadFederatedToken(big)).Throws<InvalidOperationException>();
            await Assert.That(() => EntraIdClientCredential.ReadFederatedToken(invalid)).Throws<InvalidDataException>();
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    // ================================================================ TEC.Security.Testing

    [Test]
    public async Task Test_token_issuer_uses_the_injected_clock_and_fails_after_dispose()
    {
        var at = new DateTimeOffset(2030, 5, 1, 12, 0, 0, TimeSpan.Zero);
        var issuer = new TestTokenIssuer(time: new FixedTimeProvider(at));

        var token = new JsonWebToken(issuer.CreateToken());
        issuer.Dispose();

        await Assert.That(new DateTimeOffset(token.IssuedAt, TimeSpan.Zero)).IsEqualTo(at);
        await Assert.That(() => issuer.CreateToken()).Throws<ObjectDisposedException>();
    }

    // ================================================================ apoio

    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    private static ApiKeyOptions Catalog(string hash) => new()
    {
        Keys = { ["erp-contoso"] = new ApiKeyDefinition { Hash = hash, ExpiresOn = DateTimeOffset.UtcNow.AddDays(30) } }
    };

    private static PermissionContext Context(string userId, params string[] roles) =>
        new("Test", "Test", userId, null, PrincipalKind.User, roles);

    private static ServiceProvider BuildProvider(Action<SecurityBuilder>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddTecSecurity(new ConfigurationBuilder().Build(), configure);
        return services.BuildServiceProvider();
    }

    private static JwtBearerOptions HardenedBearerOptions()
    {
        var options = new JwtBearerOptions();
        JwtHardening.ApplyDefaults(options, 16 * 1024, isDevelopment: false);
        options.TokenValidationParameters.ValidIssuer = "https://emissor.test/";
        options.TokenValidationParameters.ValidAudience = "api://teste";
        return options;
    }

    private static OpenIdConnectOptions HardenedOidcOptions()
    {
        var options = new OpenIdConnectOptions
        {
            ClientId = "client",
            Authority = "https://login.test/tenant/v2.0",
            ResponseType = OpenIdConnectResponseType.Code,
            MapInboundClaims = false,
            SaveTokens = false
        };
        options.TokenValidationParameters.ValidateIssuerSigningKey = true;
        options.TokenValidationParameters.ClockSkew = JwtHardening.DefaultClockSkew;
        options.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256];
        return options;
    }

    private sealed class ThrowingOptionsMonitor<T> : IOptionsMonitor<T>
    {
        private int _reads;

        public int Reads => Volatile.Read(ref _reads);

        public T CurrentValue
        {
            get
            {
                Interlocked.Increment(ref _reads);
                throw new OptionsValidationException(Options.DefaultName, typeof(T), ["configuração inválida"]);
            }
        }

        public T Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class SlowPermissionStore(TimeSpan delay) : IPermissionStore
    {
        private int _calls;

        public int Calls => Volatile.Read(ref _calls);

        public async ValueTask<IReadOnlyCollection<string>> GetPermissionsAsync(PermissionContext context, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            await Task.Delay(delay, cancellationToken);
            return ["pedidos:ler"];
        }
    }

    private sealed class NullPermissionStore : IPermissionStore
    {
        public ValueTask<IReadOnlyCollection<string>> GetPermissionsAsync(PermissionContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult<IReadOnlyCollection<string>>(null!);
    }

    private sealed class EmptyTenantRegistry : ITenantRegistry
    {
        public TenantInfo? FindByExternalId(string provider, string externalTenantId) => null;

        public TenantInfo? Find(string tenantId) => null;

        public IReadOnlySet<string> GetEnabledExternalIds(string provider) => new HashSet<string>();
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class FlakyTokenProvider(TimeProvider time, TimeSpan lifetime) : CachingAccessTokenProvider("Fake", time)
    {
        private readonly TimeProvider _clock = time;

        private int _calls;

        public bool Fail { get; set; }

        protected override ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken)
        {
            if (Fail)
                throw new HttpRequestException("provedor fora do ar");

            int call = Interlocked.Increment(ref _calls);
            return ValueTask.FromResult(new AccessToken($"token-{call}", _clock.GetUtcNow().Add(lifetime)));
        }
    }

    private sealed class StaticHandler(Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond());
    }

    /// <summary>Conteúdo sem tamanho conhecido (como uma resposta em partes).</summary>
    private sealed class UnknownLengthContent(int bytes) : HttpContent
    {
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            byte[] chunk = new byte[4096];
            Array.Fill(chunk, (byte)'a');
            for (int written = 0; written < bytes; written += chunk.Length)
                await stream.WriteAsync(chunk);
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
