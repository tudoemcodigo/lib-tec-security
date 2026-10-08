using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tokens;

namespace TEC.Security.Tests.Security.Adversarial;

/// <summary>
/// Vazamento de dados: segredos (token, segredo da API key, credencial do provedor) nunca aparecem em log, resposta ou
/// mensagem de exceção, e as recusas não funcionam como oráculo: o cliente recebe a mesma resposta qualquer que seja o motivo
/// (assinatura, validade, audiência, tenant inexistente ou inativo, chave desconhecida, expirada...).
/// </summary>
public class LeakageTests
{
    private static readonly string Secret = "SEGREDO" + Guid.NewGuid().ToString("N")[..12].ToUpperInvariant();

    // ---------- Sem oráculo: toda recusa responde igual ----------

    [Test]
    public async Task RejectedTokens_AllReasons_IdenticalResponse_AndTokenNeverLogged()
    {
        await using var app = await SecuredTestApp.StartAsync();
        using var other = new Testing.TestTokenIssuer(app.Issuer.Issuer, app.Issuer.Audience);
        var tokens = new Dictionary<string, string>
        {
            ["assinatura de outra chave"] = other.CreateToken(t => { t.ExternalTenantId = SecuredTestApp.Tid; t.Roles.Add("Gerente"); }),
            ["expirado"] = app.ValidToken(t => { t.IssuedAt = DateTimeOffset.UtcNow.AddHours(-1); t.Lifetime = TimeSpan.FromMinutes(5); }),
            ["ainda não válido"] = app.ValidToken(t => t.IssuedAt = DateTimeOffset.UtcNow.AddHours(1)),
            ["outra audiência"] = app.ValidToken(t => t.Audience = "api://outra"),
            ["tenant inexistente"] = app.ValidToken(t => t.ExternalTenantId = "99999999-9999-9999-9999-999999999999"),
            ["tenant inativo"] = app.ValidToken(t => t.ExternalTenantId = SecuredTestApp.InactiveTid),
            ["sem tenant (RequireTenant)"] = app.ValidToken(t => t.ExternalTenantId = null),
            ["id fora do formato"] = app.ValidToken(t => t.Subject = "id com espaço"),
            ["malformado"] = "nao.e.jwt",
        };

        var responses = new Dictionary<string, string>();
        foreach (var (reason, token) in tokens)
            responses[reason] = await DescribeAsync(app.Client, Bearer("/pedidos", token));

        string reference = responses.First().Value;
        foreach (var (reason, description) in responses)
            await Assert.That(description).IsEqualTo(reference).Because($"'{reason}' responde diferente (oráculo do motivo da recusa)");

        foreach (var token in tokens.Values.Where(t => t.Count(c => c == '.') == 2 && t.Length > 100))
        {
            await Assert.That(app.App.Logs.All).DoesNotContain(token.Split('.')[1]);
            await Assert.That(app.App.Logs.All).DoesNotContain(token.Split('.')[2]);
        }
    }

    [Test]
    public async Task RejectedApiKeys_AllReasons_IdenticalResponse_AndSecretNeverLogged()
    {
        await using var app = await SecuredTestApp.StartAsync();
        string wrongSecret = app.ApiKey.Key[..^4] + "AAAA";
        var keys = new Dictionary<string, string>
        {
            ["segredo errado"] = wrongSecret,
            ["id desconhecido"] = ApiKeyGenerator.Generate("id-desconhecido").Key,
            ["expirada"] = app.ExpiredApiKey.Key,
            ["formato inválido"] = "tec_" + Secret,
            ["vazia"] = " ",
        };

        var responses = new Dictionary<string, string>();
        foreach (var (reason, key) in keys)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/pedidos");
            request.Headers.TryAddWithoutValidation("X-Api-Key", key);
            responses[reason] = await DescribeAsync(app.Client, request);
        }

        string reference = responses.First().Value;
        foreach (var (reason, description) in responses)
            await Assert.That(description).IsEqualTo(reference).Because($"'{reason}' responde diferente (oráculo do motivo da recusa)");

        // O id (público, faz parte da chave) pode ir para a auditoria; o segredo, nunca
        foreach (string key in new[] { wrongSecret, app.ExpiredApiKey.Key, app.ApiKey.Key })
            await Assert.That(app.App.Logs.All).DoesNotContain(key[^43..]);
        await Assert.That(app.App.Logs.All).DoesNotContain(Secret);
    }

    [Test]
    public async Task ForbiddenResponse_NeverRevealsTheRequiredPermission()
    {
        await using var app = await SecuredTestApp.StartAsync();

        var response = await app.Client.SendAsync(Bearer("/pedidos", app.ValidToken(t => t.Roles.Clear())));
        string body = await response.Content.ReadAsStringAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
        await Assert.That(body).DoesNotContain("pedidos:ler");
        await Assert.That(body).DoesNotContain("Gerente");
        await Assert.That(response.Headers.CacheControl?.NoStore).IsTrue();
    }

    [Test]
    public async Task ErrorDetails_InWwwAuthenticate_OnlyInDevelopment()
    {
        await using var app = await SecuredTestApp.StartAsync(environment: "Testing");
        var response = await app.Client.SendAsync(Bearer("/pedidos", app.ValidToken(t => { t.IssuedAt = DateTimeOffset.UtcNow.AddHours(-1); t.Lifetime = TimeSpan.FromMinutes(5); })));

        string challenge = response.Headers.WwwAuthenticate.ToString();
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(challenge).DoesNotContain("error_description");
        await Assert.That(challenge).DoesNotContain("expired");
    }

    // ---------- Núcleo: mensagens e logs ----------

    [Test]
    public async Task ApiKeyValidator_Logs_NeverContainTheSecret()
    {
        var logs = new TestLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs).SetMinimumLevel(LogLevel.Trace));
        var key = ApiKeyGenerator.Generate("erp-contoso");
        var disabled = ApiKeyGenerator.Generate("erp-desativada");
        var options = new ApiKeyOptions();
        options.Keys[key.KeyId] = new ApiKeyDefinition { Hash = key.Hash, ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) };
        options.Keys[disabled.KeyId] = new ApiKeyDefinition { Hash = disabled.Hash, Enabled = false, ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) };
        var validator = new ApiKeyValidator(new TestOptionsMonitor<ApiKeyOptions>(options), logger: factory.CreateLogger<ApiKeyValidator>());

        string[] presented = [key.Key[..^1] + (key.Key[^1] == 'A' ? 'B' : 'A'), disabled.Key, ApiKeyGenerator.Generate("outra").Key, Secret, "tec_" + Secret + "_x"];
        foreach (string value in presented)
            await Assert.That(validator.Validate(value)).IsNull();

        foreach (string value in presented)
            await Assert.That(logs.All).DoesNotContain(value.Length >= 43 ? value[^43..] : value);
        await Assert.That(logs.Entries.Count(e => e.EventId == 3110)).IsEqualTo(presented.Length);
    }

    [Test]
    public async Task ServiceTokenFailure_ExceptionMessageAndResult_HideInfrastructureDetails()
    {
        using var provider = new FailingTokenProvider(new HttpRequestException($"POST https://login.contoso/{Secret}/token: client_secret={Secret}"));

        var thrown = await Assert.That(async () => await provider.GetTokenAsync(["api://x/.default"], CancellationToken.None))
            .ThrowsExactly<SecurityTokenAcquisitionException>();

        await Assert.That(thrown!.Message).DoesNotContain(Secret);
        await Assert.That(thrown.Errors[0].Message).DoesNotContain(Secret);
        await Assert.That(thrown.Code).IsEqualTo(SecurityErrors.ProviderFailureCode);
        await Assert.That(JsonSerializer.Serialize(new { thrown.Message })).DoesNotContain(Secret);
    }

    [Test]
    public async Task InvalidTenantCatalog_ErrorsNeverContainExternalIds()
    {
        // Mesmo id externo (o "segredo") em dois tenants: a mensagem diz o problema, não o valor
        var options = new TenantOptions();
        options.Items["contoso"] = new TenantDefinition { IdentityProviders = { ["EntraId"] = [Secret] } };
        options.Items["fabrikam"] = new TenantDefinition { IdentityProviders = { ["EntraId"] = [Secret] } };

        var thrown = await Assert.That(() => new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(options)))
            .Throws<InvalidOperationException>();
        await Assert.That(thrown!.Message).DoesNotContain(Secret);

        // Na recarga: a versão é recusada com log de erro, também sem o valor
        var logs = new TestLoggerProvider();
        using var factory = LoggerFactory.Create(b => b.AddProvider(logs));
        var monitor = new TestOptionsMonitor<TenantOptions>(new TenantOptions());
        using var registry = new ConfigurationTenantRegistry(monitor, factory.CreateLogger<ConfigurationTenantRegistry>());
        monitor.Set(options);

        await Assert.That(logs.Entries.Any(e => e.EventId == 3101)).IsTrue();
        await Assert.That(logs.All).DoesNotContain(Secret);
    }

    [Test]
    public async Task InvalidApiKeyCatalog_ValidationFailures_NeverContainHashes()
    {
        var options = new ApiKeyOptions();
        options.Keys["erp-contoso"] = new ApiKeyDefinition { Hash = Secret, TenantId = "tenant inválido " + Secret, ExpiresOn = null, Roles = [Secret + " x"] };

        var result = new ApiKeyOptionsValidator().Validate(null, options);

        await Assert.That(result.Failed).IsTrue();
        await Assert.That(result.FailureMessage).DoesNotContain(Secret);
    }

    [Test]
    public async Task SystemPrincipal_InvalidInput_ErrorNeverRepeatsTheValue()
    {
        var factory = new Claims.SecurityIdentityFactory(new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions())),
            new FakePermissionStore(), new TestOptionsMonitor<SecurityOptions>(new SecurityOptions()));
        var context = new Context.SecurityContext(factory);

        var badService = await context.CreateSystemPrincipalAsync(Secret);
        var badTenant = await context.CreateSystemPrincipalAsync("servico-ok", "tenant " + Secret);

        await Assert.That(badService.IsFailure && badTenant.IsFailure).IsTrue();
        await Assert.That(badService.Error!.Message + badService.Error.ToString()).DoesNotContain(Secret);
        await Assert.That(badTenant.Error!.Message + badTenant.Error.ToString()).DoesNotContain(Secret);
    }

    [Test]
    public async Task GeneratedApiKeyAndAccessToken_ToString_HideSecrets()
    {
        var key = ApiKeyGenerator.Generate("erp-contoso");
        var token = new AccessToken("eyJ" + Secret, DateTimeOffset.UtcNow.AddHours(1));

        await Assert.That(key.ToString()).DoesNotContain(key.Key);
        await Assert.That(key.ToString()).DoesNotContain(key.Key[^43..]);
        await Assert.That(token.ToString() ?? "").DoesNotContain(Secret);
    }

    [Test]
    public async Task IdentityRejection_LogInjection_IsNotPossible()
    {
        // Identificador com quebra de linha (tentativa de forjar uma linha de log): recusado, e o texto nunca chega ao log
        var logs = new TestLoggerProvider();
        using var loggerFactory = LoggerFactory.Create(b => b.AddProvider(logs));
        var factory = new Claims.SecurityIdentityFactory(new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions())),
            new FakePermissionStore(), new TestOptionsMonitor<SecurityOptions>(new SecurityOptions()), loggerFactory.CreateLogger<Claims.SecurityIdentityFactory>());

        var result = await factory.CreateAsync(new Claims.ExternalIdentity
        {
            Scheme = "Test\nINFO acesso liberado " + Secret,
            Provider = "Test",
            UserId = "u\n" + Secret,
            Kind = PrincipalKind.User,
            Name = "Nome\r\n" + Secret
        });

        await Assert.That(result.IsFailure).IsTrue();
        await Assert.That(logs.All).DoesNotContain(Secret);
    }

    private static HttpRequestMessage Bearer(string path, string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    /// <summary>Status, headers de autenticação e corpo, sem traceId e timestamp (mudam a cada requisição).</summary>
    private static async Task<string> DescribeAsync(HttpClient client, HttpRequestMessage request)
    {
        using (request)
        using (var response = await client.SendAsync(request))
        {
            string body = await response.Content.ReadAsStringAsync();
            using var json = JsonDocument.Parse(body);
            var fields = json.RootElement.EnumerateObject()
                .Where(p => p.Name is not ("traceId" or "timestamp"))
                .Select(p => $"{p.Name}={p.Value.GetRawText()}");
            return $"{(int)response.StatusCode} | {response.Headers.WwwAuthenticate} | {response.Content.Headers.ContentType} | {string.Join(';', fields)}";
        }
    }

    private sealed class FailingTokenProvider(Exception failure) : CachingAccessTokenProvider("Falha")
    {
        protected override ValueTask<AccessToken> AcquireTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken) =>
            ValueTask.FromException<AccessToken>(failure);
    }
}
