using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.DependencyInjection;
using TEC.Security.Tenants;
using TEC.Security.Testing;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests;

/// <summary>
/// Regressões da revisão técnica de 2026-10-19 (<c>docs/revisao-tecnica.md</c>), uma por achado. SEC-01, SEC-02 e SEC-11
/// ficam em <see cref="ResilienceTests"/>; SEC-07 em <see cref="EntraIdApiTests"/>; SEC-12 em <see cref="OnBehalfOfHandlerTests"/>.
/// </summary>
public class TechnicalReviewRegressionTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 19, 12, 0, 0, TimeSpan.Zero);

    // ================================================================ SEC-01: tempo limite do IPermissionStore

    [Test]
    public async Task Permission_store_timeout_becomes_provider_failure_instead_of_unhandled_cancellation()
    {
        var store = new FakePermissionStore { Resolve = _ => throw new TaskCanceledException("tempo limite do HttpClient") };
        var factory = new SecurityIdentityFactory(new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions())),
            store, new TestOptionsMonitor<SecurityOptions>(new SecurityOptions()));

        var result = await factory.CreateAsync(User());

        await Assert.That(result.IsSuccess).IsFalse();
        await Assert.That(result.Error!.Code).IsEqualTo(SecurityErrors.ProviderFailureCode);
    }

    [Test]
    public async Task Caller_cancellation_still_propagates_from_permission_store()
    {
        using var cts = new CancellationTokenSource();
        var store = new FakePermissionStore
        {
            Resolve = _ =>
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
        };
        var factory = new SecurityIdentityFactory(new ConfigurationTenantRegistry(new TestOptionsMonitor<TenantOptions>(new TenantOptions())),
            store, new TestOptionsMonitor<SecurityOptions>(new SecurityOptions()));

        await Assert.That(async () => await factory.CreateAsync(User(), cts.Token)).Throws<OperationCanceledException>();
    }

    // ================================================================ SEC-03: recarga com erro não desfaz revogação

    [Test]
    public async Task Api_key_revocation_applies_even_when_another_key_in_the_same_edit_is_invalid()
    {
        // Cenário do achado: desativa a chave vazada e, na mesma edição, cadastra a nova com o hash truncado
        var leaked = ApiKeyGenerator.Generate("erp-contoso");
        var other = ApiKeyGenerator.Generate("erp-fabrikam");
        var replacement = ApiKeyGenerator.Generate("erp-contoso-2027");
        string expires = DateTimeOffset.UtcNow.AddDays(30).ToString("O", CultureInfo.InvariantCulture);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:ApiKeys:Keys:erp-contoso:Hash"] = leaked.Hash,
            ["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = expires,
            ["Security:ApiKeys:Keys:erp-fabrikam:Hash"] = other.Hash,
            ["Security:ApiKeys:Keys:erp-fabrikam:ExpiresOn"] = expires
        }).Build();
        var logs = new TestLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddTecSecurity(configuration);
        await using var provider = services.BuildServiceProvider();
        var validator = provider.GetRequiredService<ApiKeyValidator>();
        bool before = validator.Validate(leaked.Key) is not null;

        configuration["Security:ApiKeys:Keys:erp-contoso:Enabled"] = "false";
        configuration["Security:ApiKeys:Keys:erp-contoso-2027:Hash"] = replacement.Hash[..20];
        configuration["Security:ApiKeys:Keys:erp-contoso-2027:ExpiresOn"] = expires;
        Reload(configuration);

        await Assert.That(before).IsTrue();
        await Assert.That(validator.Validate(leaked.Key)).IsNull();          // revogação vale (antes: continuava aceita)
        await Assert.That(validator.Validate(replacement.Key)).IsNull();     // entrada com erro: falha fechada
        await Assert.That(validator.Validate(other.Key)).IsNotNull();        // chave válida não afetada
        await Assert.That(logs.Entries.Count(e => e.EventId == 3111)).IsEqualTo(1);
    }

    [Test]
    public async Task Api_key_removal_applies_even_when_header_name_in_the_same_edit_is_invalid()
    {
        var removed = ApiKeyGenerator.Generate("erp-contoso");
        var kept = ApiKeyGenerator.Generate("erp-fabrikam");
        string expires = DateTimeOffset.UtcNow.AddDays(30).ToString("O", CultureInfo.InvariantCulture);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:ApiKeys:HeaderName"] = "X-Chave",
            ["Security:ApiKeys:Keys:erp-contoso:Hash"] = removed.Hash,
            ["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = expires,
            ["Security:ApiKeys:Keys:erp-fabrikam:Hash"] = kept.Hash,
            ["Security:ApiKeys:Keys:erp-fabrikam:ExpiresOn"] = expires
        }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecSecurity(configuration);
        await using var provider = services.BuildServiceProvider();
        var validator = provider.GetRequiredService<ApiKeyValidator>();
        bool before = validator.Validate(removed.Key) is not null;

        configuration["Security:ApiKeys:HeaderName"] = "Authorization";
        configuration["Security:ApiKeys:Keys:erp-contoso:Hash"] = null;
        configuration["Security:ApiKeys:Keys:erp-contoso:ExpiresOn"] = null;
        Reload(configuration);

        await Assert.That(before).IsTrue();
        await Assert.That(validator.Validate(removed.Key)).IsNull();
        await Assert.That(validator.Validate(kept.Key)).IsNotNull();
        await Assert.That(validator.HeaderName).IsEqualTo("X-Chave");
    }

    [Test]
    public async Task Invalid_reload_without_unvalidated_reader_refuses_every_key()
    {
        // Validador criado fora do AddTecSecurity: sem como ler a versão nova, falha fechada (antes: versão anterior valia)
        var key = ApiKeyGenerator.Generate("erp-contoso");
        var options = new ApiKeyOptions { Keys = { [key.KeyId] = new ApiKeyDefinition { Hash = key.Hash, ExpiresOn = Now.AddDays(30) } } };
        var monitor = new SwitchableOptionsMonitor<ApiKeyOptions>(options);
        var clock = new ManualTimeProvider(Now);
        var validator = new ApiKeyValidator(monitor, clock);
        bool before = validator.Validate(key.Key) is not null;

        monitor.Invalid = true;

        await Assert.That(before).IsTrue();
        await Assert.That(validator.Validate(key.Key)).IsNull();
    }

    // ================================================================ SEC-05: falha passageira do store não desloga

    [Test]
    public async Task Transient_permission_store_failure_rejects_request_but_keeps_web_session()
    {
        var (context, auth, properties, validatedAt) = await SessionAsync(store => store.Resolve = _ => throw new HttpRequestException("banco fora"));

        await SecurityBuilderWebLoginExtensions.ValidateSessionAsync(context, WebDefinition());

        await Assert.That(context.Principal).IsNull();                 // esta requisição fica sem identidade
        await Assert.That(auth.SignOuts).IsEqualTo(0);                 // antes: SignOutAsync apagava o cookie
        await Assert.That(properties.Items[SecurityBuilderWebLoginExtensions.ValidatedAtKey]).IsEqualTo(validatedAt);
    }

    [Test]
    public async Task Provider_rule_rejection_still_ends_web_session()
    {
        var (context, auth, _, _) = await SessionAsync(_ => { });

        await SecurityBuilderWebLoginExtensions.ValidateSessionAsync(context, WebDefinition(allowed: false));

        await Assert.That(context.Principal).IsNull();
        await Assert.That(auth.SignOuts).IsEqualTo(1);
    }

    // ================================================================ SEC-06: permissões por tenant sem diferenciar maiúsculas

    [Test]
    public async Task Tenant_permissions_match_the_catalog_ignoring_case_and_unknown_tenants_are_reported()
    {
        const string Tid = "11111111-1111-1111-1111-111111111111";
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:RolesAsPermissions"] = "false",
            ["Security:Tenants:Contoso:IdentityProviders:OpenIdConnect:0"] = Tid,
            ["Security:Permissions:Tenants:contoso:Roles:Vendedor:0"] = "pedidos:ler",
            ["Security:Permissions:Tenants:fabrikam:Roles:Vendedor:0"] = "pedidos:ler"
        }).Build();
        var logs = new TestLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddTecSecurity(configuration);
        await using var provider = services.BuildServiceProvider();
        foreach (var hosted in provider.GetServices<IHostedService>())
            await hosted.StartAsync(default);

        var result = await provider.GetRequiredService<SecurityIdentityFactory>().CreateAsync(User(Tid, roles: ["Vendedor"]));

        await Assert.That(new SecurityUser(result.Value).HasPermission("pedidos:ler")).IsTrue();
        await Assert.That(logs.Entries.Count(e => e.EventId == 3102)).IsEqualTo(1);
        await Assert.That(logs.Entries.Single(e => e.EventId == 3102).Message).Contains("fabrikam");
    }

    // ================================================================ SEC-08: ganchos de validação conferidos na subida

    [Test]
    [Arguments("resolver")]
    [Arguments("resolver-config")]
    [Arguments("validator")]
    [Arguments("reader")]
    [Arguments("handlers")]
    [Arguments("handler-size")]
    [Arguments("legacy-validators")]
    [Arguments("decryption")]
    public async Task Weakening_hooks_prevent_startup(string hook)
    {
        using var issuer = new TestTokenIssuer();

        await Assert.That(async () =>
        {
            await using var app = await TestApp.StartAsync(
                b =>
                {
                    b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer));
                    b.Services.PostConfigure<JwtBearerOptions>("Test", o => Weaken(o, hook));
                },
                a => a.MapGet("/x", () => "ok"));
        }).Throws<OptionsValidationException>();
    }

    private static void Weaken(JwtBearerOptions o, string hook)
    {
        var p = o.TokenValidationParameters;
        switch (hook)
        {
            case "resolver":
                p.IssuerSigningKeyResolver = (_, _, _, _) => [];
                break;
            case "resolver-config":
                p.IssuerSigningKeyResolverUsingConfiguration = (_, _, _, _, _) => [];
                break;
            case "validator":
                p.IssuerSigningKeyValidator = (_, _, _) => true;
                break;
            case "reader":
                p.TokenReader = (token, _) => new JsonWebToken(token);
                break;
            case "handlers":
                o.TokenHandlers.Add(new JsonWebTokenHandler { MapInboundClaims = false });
                break;
            case "handler-size":
                o.TokenHandlers.Clear();
                o.TokenHandlers.Add(new JsonWebTokenHandler { MapInboundClaims = false });   // tamanho padrão (250 KB)
                break;
            case "legacy-validators":
                o.UseSecurityTokenValidators = true;
                break;
            case "decryption":
                p.TokenDecryptionKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
                break;
        }
    }

    // ================================================================ SEC-10: autorização fechada por padrão conferida na subida

    [Test]
    public async Task Removing_the_fallback_policy_after_AddAspNetCore_prevents_startup()
    {
        using var issuer = new TestTokenIssuer();

        await Assert.That(async () =>
        {
            await using var app = await TestApp.StartAsync(
                b =>
                {
                    b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer));
                    b.Services.AddAuthorization(o => o.FallbackPolicy = null);
                },
                a => a.MapGet("/x", () => "ok"));
        }).Throws<OptionsValidationException>();
    }

    [Test]
    public async Task Custom_policy_provider_registered_before_AddAspNetCore_is_refused()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAuthorizationPolicyProvider, CustomPolicyProvider>();

        await Assert.That(() => services.AddTecSecurity(new ConfigurationBuilder().Build(), s => s.AddAspNetCore()))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task Custom_policy_provider_registered_after_AddAspNetCore_prevents_startup()
    {
        using var issuer = new TestTokenIssuer();

        await Assert.That(async () =>
        {
            await using var app = await TestApp.StartAsync(
                b =>
                {
                    b.Services.AddTecSecurity(b.Configuration, s => s.AddAspNetCore().AddTestJwt(issuer));
                    b.Services.AddSingleton<IAuthorizationPolicyProvider, CustomPolicyProvider>();
                },
                a => a.MapGet("/x", () => "ok"));
        }).Throws<InvalidOperationException>();
    }

    // ================================================================ SEC-13: log de recusa de API key limitado

    [Test]
    public async Task Repeated_api_key_rejections_are_logged_once_per_interval_with_the_count()
    {
        var key = ApiKeyGenerator.Generate("erp-contoso");
        var options = new ApiKeyOptions { Keys = { [key.KeyId] = new ApiKeyDefinition { Hash = key.Hash, ExpiresOn = Now.AddDays(30) } } };
        var logs = new TestLoggerProvider();
        var clock = new ManualTimeProvider(Now);
        var validator = new ApiKeyValidator(new TestOptionsMonitor<ApiKeyOptions>(options), clock,
            new LoggerFactory([logs]).CreateLogger<ApiKeyValidator>());
        string wrong = ApiKeyGenerator.Generate("erp-contoso").Key;

        for (int i = 0; i < 100; i++)
            _ = validator.Validate(wrong);
        int duringBurst = logs.Entries.Count(e => e.EventId == 3110);
        clock.Now = Now + ApiKeyValidator.RejectionLogInterval;
        _ = validator.Validate(wrong);

        await Assert.That(duringBurst).IsEqualTo(1);
        await Assert.That(logs.Entries.Count(e => e.EventId == 3110)).IsEqualTo(2);
        await Assert.That(logs.Entries.Last(e => e.EventId == 3110).Message).Contains("99 recusas iguais omitidas");
    }

    [Test]
    public async Task Rejection_log_limiter_memory_is_bounded_for_invented_ids()
    {
        var limiter = new RejectionLogLimiter(new ManualTimeProvider(Now), TimeSpan.FromMinutes(1), maxEntries: 10);

        int logged = Enumerable.Range(0, 1_000).Count(i => limiter.TryEnter($"id-{i}", "id desconhecido", out _));

        // 10 ids com entrada própria + 1 entrada compartilhada pelos demais
        await Assert.That(logged).IsEqualTo(11);
    }

    // ================================================================ apoio

    /// <summary>
    /// Recarrega a configuração. O OptionsMonitor relê as opções no próprio aviso de mudança e a validação lança ali (comportamento
    /// do Microsoft.Extensions.Options); a versão efetiva é a que o validador aplica na leitura seguinte.
    /// </summary>
    private static void Reload(IConfigurationRoot configuration)
    {
        try
        {
            configuration.Reload();
        }
        catch (AggregateException exception) when (exception.InnerExceptions.All(e => e is OptionsValidationException))
        {
        }
    }

    private static ExternalIdentity User(string? externalTenant = null, string[]? roles = null) => new()
    {
        Scheme = "Funcionarios",
        Provider = "OpenIdConnect",
        UserId = "aaaaaaaa-0000-0000-0000-000000000001",
        Kind = PrincipalKind.User,
        ExternalTenantId = externalTenant,
        Roles = roles ?? []
    };

    private static WebLoginDefinition WebDefinition(bool allowed = true) => new()
    {
        Scheme = "Web",
        Provider = "Teste",
        CreateIdentity = (Microsoft.AspNetCore.Authentication.OpenIdConnect.TokenValidatedContext _, out string reason) =>
        {
            reason = "não usado";
            return null;
        },
        IsSessionAllowed = (_, _) => allowed
    };

    private static async Task<(CookieValidatePrincipalContext Context, RecordingAuthenticationService Auth, AuthenticationProperties Properties,
        string ValidatedAt)> SessionAsync(Action<FakePermissionStore> afterLogin)
    {
        var store = new FakePermissionStore();
        var auth = new RecordingAuthenticationService();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddTecSecurity(new ConfigurationBuilder().Build());
        services.AddSingleton<IPermissionStore>(store);
        services.AddSingleton<IAuthenticationService>(auth);
        var provider = services.BuildServiceProvider();

        var principal = (await provider.GetRequiredService<SecurityIdentityFactory>().CreateAsync(new ExternalIdentity
        {
            Scheme = "Web",
            Provider = "Teste",
            UserId = "u1",
            Kind = PrincipalKind.User
        })).Value;
        afterLogin(store);

        var now = DateTimeOffset.UtcNow;
        string validatedAt = now.AddHours(-1).ToString("O", CultureInfo.InvariantCulture);
        var properties = new AuthenticationProperties();
        properties.Items[SecurityBuilderWebLoginExtensions.SignedInAtKey] = now.AddMinutes(-70).ToString("O", CultureInfo.InvariantCulture);
        properties.Items[SecurityBuilderWebLoginExtensions.ValidatedAtKey] = validatedAt;
        var http = new DefaultHttpContext { RequestServices = provider };
        var context = new CookieValidatePrincipalContext(http, new AuthenticationScheme("Web", null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(), new AuthenticationTicket(principal, properties, "Web"));
        return (context, auth, properties, validatedAt);
    }

    private sealed class RecordingAuthenticationService : IAuthenticationService
    {
        public int SignOuts;

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => Task.FromResult(AuthenticateResult.NoResult());

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => Task.CompletedTask;

        public Task SignInAsync(HttpContext context, string? scheme, System.Security.Claims.ClaimsPrincipal principal, AuthenticationProperties? properties) =>
            Task.CompletedTask;

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            Interlocked.Increment(ref SignOuts);
            return Task.CompletedTask;
        }
    }

    private sealed class CustomPolicyProvider(IOptions<AuthorizationOptions> options) : DefaultAuthorizationPolicyProvider(options);

    /// <summary>Monitor que passa a lançar <see cref="OptionsValidationException"/> (recarga inválida).</summary>
    private sealed class SwitchableOptionsMonitor<T>(T value) : IOptionsMonitor<T> where T : class
    {
        public bool Invalid { get; set; }

        public T CurrentValue => Invalid ? throw new OptionsValidationException(Options.DefaultName, typeof(T), ["inválido"]) : value;

        public T Get(string? name) => CurrentValue;

        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
