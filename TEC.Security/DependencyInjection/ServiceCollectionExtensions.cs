using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.Claims;
using TEC.Security.Configuration;
using TEC.Security.Context;
using TEC.Security.Permissions;
using TEC.Security.Tenants;

namespace TEC.Security.DependencyInjection;

/// <summary>Registro do TEC.Security no container de injeção de dependência.</summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registra o núcleo de segurança: <see cref="ISecurityUser"/>, <see cref="ICurrentUser"/> (TEC.Core) e
    /// <see cref="ICurrentTenant"/> (Scoped), <see cref="ISecurityContext"/>, <see cref="ITenantRegistry"/>,
    /// <see cref="IPermissionStore"/>, <see cref="SecurityIdentityFactory"/> e <see cref="ApiKeyValidator"/> (Singleton), com as
    /// opções da seção <c>Security</c> (recarregáveis).
    /// </summary>
    /// <remarks>
    /// <para>Os provedores de identidade são adicionados no <paramref name="configure"/> pelos pacotes de provedor
    /// (ex.: <c>security.AddAspNetCore()</c> e <c>security.AddEntraIdApi(...)</c>).</para>
    /// <para>Validação na inicialização (o host não sobe): cadastro de tenants e de API keys.</para>
    /// </remarks>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez.</exception>
    /// <example>
    /// <code>
    /// builder.Services.AddTecSecurity(builder.Configuration, security =&gt; security
    ///     .AddAspNetCore()
    ///     .AddEntraIdApi("Funcionarios", builder.Configuration.GetSection("Security:EntraId")));
    /// </code>
    /// </example>
    public static SecurityBuilder AddTecSecurity(this IServiceCollection services, IConfiguration configuration,
        Action<SecurityBuilder>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        if (services.Any(d => d.ServiceType == typeof(SecurityBuilder)))
            throw new InvalidOperationException("AddTecSecurity já foi chamado. Configure a segurança em uma única chamada.");

        var builder = new SecurityBuilder(services, configuration);
        services.AddSingleton(builder);

        services.AddOptions();
        services.AddLogging();
        services.TryAddSingleton(TimeProvider.System);

        services.Configure<SecurityOptions>(configuration.GetSection(SecurityOptions.SectionName));
        services.Configure<PermissionOptions>(configuration.GetSection(PermissionOptions.SectionName));
        services.Configure<ApiKeyOptions>(configuration.GetSection(ApiKeyOptions.SectionName));

        var tenantSection = configuration.GetSection(TenantOptions.SectionName);
        services.AddOptions<TenantOptions>().Configure(o => tenantSection.Bind(o.Items));
        services.AddSingleton<IOptionsChangeTokenSource<TenantOptions>>(new ConfigurationChangeTokenSource<TenantOptions>(tenantSection));

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<ApiKeyOptions>, ApiKeyOptionsValidator>());
        services.AddOptions<ApiKeyOptions>().ValidateOnStart();

        configure?.Invoke(builder);

        // ---------- Tenants ----------
        if (builder.TenantRegistryType is { } registryType)
            services.AddSingleton(sp => (ITenantRegistry)sp.GetRequiredService(registryType));
        else
            services.AddSingleton<ITenantRegistry>(sp => new ConfigurationTenantRegistry(sp.GetRequiredService<IOptionsMonitor<TenantOptions>>(),
                sp.GetService<ILogger<ConfigurationTenantRegistry>>()));

        // ---------- Permissões ----------
        if (builder.PermissionStoreType is { } storeType)
        {
            services.AddSingleton<IPermissionStore>(sp =>
            {
                var store = (IPermissionStore)sp.GetRequiredService(storeType);
                return builder.PermissionCacheDuration is { } duration ? new CachingPermissionStore(store, duration) : store;
            });
        }
        else
        {
            services.AddSingleton<IPermissionStore, ConfigurationPermissionStore>();
        }

        // ---------- Identidade ----------
        services.AddSingleton(sp => new SecurityIdentityFactory(sp.GetRequiredService<ITenantRegistry>(),
            sp.GetRequiredService<IPermissionStore>(), sp.GetRequiredService<IOptionsMonitor<SecurityOptions>>(),
            sp.GetService<ILogger<SecurityIdentityFactory>>()));
        services.AddSingleton(sp => new SecurityContext(sp.GetRequiredService<SecurityIdentityFactory>()));
        services.AddSingleton<ISecurityContext>(sp => sp.GetRequiredService<SecurityContext>());
        services.TryAddSingleton<IPrincipalSource>(sp => sp.GetRequiredService<SecurityContext>());

        services.AddScoped(sp => new CurrentSecurityUser(sp.GetRequiredService<IPrincipalSource>(), sp.GetRequiredService<ITenantRegistry>()));
        services.AddScoped<ISecurityUser>(sp => sp.GetRequiredService<CurrentSecurityUser>());
        services.AddScoped<ICurrentUser>(sp => sp.GetRequiredService<CurrentSecurityUser>());
        services.AddScoped<ICurrentTenant>(sp => sp.GetRequiredService<CurrentSecurityUser>());

        services.AddSingleton(sp => new ApiKeyValidator(sp.GetRequiredService<IOptionsMonitor<ApiKeyOptions>>(),
            sp.GetService<TimeProvider>(), sp.GetService<ILogger<ApiKeyValidator>>()));

        services.AddHostedService<SecurityStartupValidator>();

        return builder;
    }
}

/// <summary>Cria o cadastro de tenants na inicialização do host: cadastro inválido impede a aplicação de subir.</summary>
internal sealed class SecurityStartupValidator(ITenantRegistry tenants) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        GC.KeepAlive(tenants);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
