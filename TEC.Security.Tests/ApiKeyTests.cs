using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Core.Security;
using TEC.Security.ApiKeys;
using TEC.Security.Configuration;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests;

/// <summary>API keys: geração, hash, validação em tempo constante e cadastro.</summary>
public class ApiKeyTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 5, 12, 0, 0, TimeSpan.Zero);

    private static (ApiKeyValidator Validator, GeneratedApiKey Key, ApiKeyOptions Options, TestLoggerProvider Logs) Create(
        Action<ApiKeyDefinition>? configure = null)
    {
        var key = ApiKeyGenerator.Generate("erp-contoso");
        var definition = new ApiKeyDefinition { Hash = key.Hash, ExpiresOn = Now.AddDays(30), TenantId = "contoso", Permissions = ["pedidos:ler"] };
        configure?.Invoke(definition);
        var options = new ApiKeyOptions { Keys = { [key.KeyId] = definition } };
        var logs = new TestLoggerProvider();
        var validator = new ApiKeyValidator(new TestOptionsMonitor<ApiKeyOptions>(options), new ManualTimeProvider(Now),
            new LoggerFactory([logs]).CreateLogger<ApiKeyValidator>());
        return (validator, key, options, logs);
    }

    [Test]
    public async Task Generated_key_has_256_bits_tec_format_and_masked_ToString()
    {
        var key = ApiKeyGenerator.Generate("erp-contoso");

        await Assert.That(key.Key).StartsWith("tec_erp-contoso_");
        await Assert.That(key.Key.Length).IsEqualTo("tec_erp-contoso_".Length + 43);
        await Assert.That(key.ToString()).DoesNotContain(key.Key);
        await Assert.That(key.Hash).IsNotEqualTo(key.Key);
        await Assert.That(ApiKeyGenerator.Generate("erp-contoso").Key).IsNotEqualTo(key.Key);
    }

    [Test]
    public async Task Valid_key_creates_application_identity()
    {
        var (validator, key, _, _) = Create();

        var identity = validator.Validate(key.Key);

        await Assert.That(identity).IsNotNull();
        await Assert.That(identity!.Kind).IsEqualTo(PrincipalKind.Application);
        await Assert.That(identity.UserId).IsEqualTo("apikey:erp-contoso");
        await Assert.That(identity.TenantId).IsEqualTo("contoso");
    }

    [Test]
    public async Task Tampered_secret_is_rejected_and_never_logged()
    {
        var (validator, key, _, logs) = Create();
        // Adultera um caractere do MEIO do segredo: trocar o último poderia gerar Base64Url não canônico (bits finais),
        // recusado já como "formato inválido", e o teste deixaria de exercitar a comparação do hash
        int position = key.Key.Length - 10;
        string tampered = key.Key[..position] + (key.Key[position] == 'A' ? 'B' : 'A') + key.Key[(position + 1)..];

        var identity = validator.Validate(tampered);

        await Assert.That(identity).IsNull();
        await Assert.That(logs.All).DoesNotContain(tampered);
        await Assert.That(logs.All).DoesNotContain(key.Key[16..]);
        await Assert.That(logs.All).Contains("erp-contoso");
    }

    [Test]
    public async Task Expired_disabled_or_unbounded_key_is_rejected()
    {
        var expired = Create(d => d.ExpiresOn = Now.AddSeconds(-1));
        var disabled = Create(d => d.Enabled = false);
        var noExpiry = Create(d => d.ExpiresOn = null);

        await Assert.That(expired.Validator.Validate(expired.Key.Key)).IsNull();
        await Assert.That(disabled.Validator.Validate(disabled.Key.Key)).IsNull();
        await Assert.That(noExpiry.Validator.Validate(noExpiry.Key.Key)).IsNull();
    }

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments("Bearer abc")]
    [Arguments("tec_erp-contoso")]
    [Arguments("tec_ERP_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [Arguments("tec_erp-contoso_curto")]
    public async Task Invalid_format_is_rejected(string? presented)
    {
        var (validator, _, _, _) = Create();

        await Assert.That(validator.Validate(presented)).IsNull();
    }

    [Test]
    public async Task Key_of_another_id_is_not_accepted()
    {
        var (validator, _, options, _) = Create();
        var other = ApiKeyGenerator.Generate("outro-sistema");
        options.Keys["outro-sistema"] = new ApiKeyDefinition { Hash = ApiKeyGenerator.Generate("x-y-z").Hash, ExpiresOn = Now.AddDays(1) };

        await Assert.That(validator.Validate(other.Key)).IsNull();
    }

    [Test]
    public async Task Invalid_catalog_fails_options_validation()
    {
        var options = new ApiKeyOptions
        {
            HeaderName = "Authorization",
            Keys =
            {
                ["Maiuscula"] = new ApiKeyDefinition { Hash = "x", ExpiresOn = Now },
                ["sem-validade"] = new ApiKeyDefinition { Hash = ApiKeyGenerator.Generate("sem-validade").Hash },
                ["papel-ruim"] = new ApiKeyDefinition { Hash = ApiKeyGenerator.Generate("papel-ruim").Hash, ExpiresOn = Now, Roles = ["com espaço"] }
            }
        };

        var result = new ApiKeyOptionsValidator().Validate(Options.DefaultName, options);

        await Assert.That(result.Failed).IsTrue();
        await Assert.That(result.Failures!.Count()).IsEqualTo(4);
    }
}
