using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.AspNetCore.Internal;
using TEC.Security.Claims;
using TEC.Security.Configuration;
using TEC.Security.Context;
using TEC.Security.DependencyInjection;
using TEC.Security.Diagnostics;

namespace TEC.Security.AspNetCore;

/// <summary>Integração do TEC.Security com ASP.NET Core.</summary>
public static class SecurityBuilderAspNetCoreExtensions
{
    /// <summary>
    /// Configura autenticação e autorização do ASP.NET Core: esquema padrão <see cref="SecurityAspNetCoreOptions.DefaultScheme"/>
    /// (escolhe o provedor por requisição), DefaultPolicy e FallbackPolicy exigindo identidade normalizada (fechado por padrão),
    /// <see cref="TecAuthorizeAttribute"/>, respostas 401/403 padronizadas, conferência dos endpoints na inicialização e
    /// <c>ISecurityUser</c> a partir do <c>HttpContext.User</c>.
    /// </summary>
    /// <remarks>
    /// No pipeline: <c>app.UseAuthentication(); app.UseAuthorization();</c> (o <c>WebApplication</c> adiciona os dois
    /// automaticamente quando os serviços estão registrados). Adicione os provedores em seguida (ex.: <c>AddEntraIdApi</c>).
    /// </remarks>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez ou opções inválidas.</exception>
    public static SecurityBuilder AddAspNetCore(this SecurityBuilder builder, Action<SecurityAspNetCoreOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        if (builder.Properties.ContainsKey(typeof(SecuritySchemes)))
            throw new InvalidOperationException("AddAspNetCore já foi chamado.");

        var options = new SecurityAspNetCoreOptions();
        configure?.Invoke(options);
        options.Validate();

        var schemes = new SecuritySchemes();
        builder.Properties[typeof(SecuritySchemes)] = schemes;
        builder.Properties[typeof(SecurityAspNetCoreOptions)] = options;

        var services = builder.Services;
        services.AddSingleton(schemes);
        services.AddSingleton(options);
        services.AddHttpContextAccessor();
        services.RemoveAll<IPrincipalSource>();
        services.AddSingleton<IPrincipalSource>(sp =>
            new HttpPrincipalSource(sp.GetRequiredService<Abstractions.ISecurityContext>(), sp.GetRequiredService<IHttpContextAccessor>()));

        services.AddSingleton(sp => new TecSchemeSelector(schemes, options, sp.GetRequiredService<ApiKeyValidator>()));

        services.AddAuthentication(o =>
            {
                o.DefaultScheme = SecurityAspNetCoreOptions.DefaultScheme;
                o.DefaultChallengeScheme = SecurityAspNetCoreOptions.DefaultScheme;
                o.DefaultForbidScheme = SecurityAspNetCoreOptions.DefaultScheme;
            })
            .AddPolicyScheme(SecurityAspNetCoreOptions.DefaultScheme, "TEC.Security", _ => { })
            .AddScheme<AuthenticationSchemeOptions, NoCredentialsHandler>(SecurityAspNetCoreOptions.NoCredentialsScheme, _ => { });

        // O seletor depende do container (header de API key): configurado aqui, não no AddPolicyScheme
        services.AddOptions<PolicySchemeOptions>(SecurityAspNetCoreOptions.DefaultScheme)
            .Configure<TecSchemeSelector>((o, selector) => o.ForwardDefaultSelector = selector.Select);

        var tecPolicy = new AuthorizationPolicyBuilder().AddRequirements(TecAuthenticatedRequirement.Instance).Build();
        services.AddAuthorization(o =>
        {
            o.DefaultPolicy = tecPolicy;
            o.FallbackPolicy = tecPolicy;
            o.InvokeHandlersAfterFailure = false;
        });
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IAuthorizationHandler, TecAuthorizationHandler>());
        services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, TecAuthorizationResultHandler>();
        services.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter, EndpointSecurityValidator>();

        // Policies TEC|... do [TecAuthorize] (valem também em hubs SignalR e no AuthorizeRouteView do Blazor)
        services.RemoveAll<IAuthorizationPolicyProvider>();
        services.AddSingleton<IAuthorizationPolicyProvider, TecAuthorizationPolicyProvider>();

        // Controles obrigatórios conferidos depois de toda configuração, e na inicialização
        services.AddSingleton<SecurityOptionsValidators>();
        services.AddSingleton<IValidateOptions<JwtBearerOptions>>(sp => sp.GetRequiredService<SecurityOptionsValidators>());
        services.AddSingleton<IValidateOptions<Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationOptions>>(sp =>
            sp.GetRequiredService<SecurityOptionsValidators>());
        services.AddSingleton<IValidateOptions<Microsoft.AspNetCore.Authentication.OpenIdConnect.OpenIdConnectOptions>>(sp =>
            sp.GetRequiredService<SecurityOptionsValidators>());
        services.AddHostedService<SecuritySchemesStartupValidator>();

        return builder;
    }

    /// <summary>
    /// Aceita API keys (header <c>Security:ApiKeys:HeaderName</c>, padrão <c>X-Api-Key</c>) cadastradas em
    /// <c>Security:ApiKeys:Keys</c>, como identidades de aplicação. Gere chaves com <see cref="ApiKeyGenerator.Generate"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">Sem <see cref="AddAspNetCore"/> antes.</exception>
    public static SecurityBuilder AddApiKeys(this SecurityBuilder builder, string scheme = ApiKeyValidator.ProviderName)
    {
        ArgumentNullException.ThrowIfNull(builder);
        GetSchemes(builder).SetApiKey(scheme);
        builder.Services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(scheme, _ => { });
        return builder;
    }

    /// <summary>
    /// Registra um provedor de tokens bearer (JWT) com os padrões endurecidos de <see cref="JwtHardening"/>, a escolha do esquema
    /// pelo token e a normalização da identidade. Uso pelos pacotes de provedor (ex.: <c>AddEntraIdApi</c>).
    /// </summary>
    /// <exception cref="InvalidOperationException">Sem <see cref="AddAspNetCore"/> antes, ou esquema repetido.</exception>
    public static SecurityBuilder AddJwtBearerProvider(this SecurityBuilder builder, JwtProviderDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(definition);

        var schemes = GetSchemes(builder);
        var options = (SecurityAspNetCoreOptions)builder.Properties[typeof(SecurityAspNetCoreOptions)];
        schemes.AddBearer(new BearerProviderRegistration(definition.Scheme, definition.Provider, definition.CanHandle));

        builder.Services.AddAuthentication().AddJwtBearer(definition.Scheme, _ => { });
        builder.Services.AddOptions<JwtBearerOptions>(definition.Scheme)
            .Configure<IServiceProvider>((o, sp) =>
            {
                bool isDevelopment = sp.GetService<IHostEnvironment>()?.IsDevelopment() == true;
                JwtHardening.ApplyDefaults(o, options.MaxTokenLength, isDevelopment);
                o.Events = new TecJwtBearerEvents(definition, options);
                definition.Configure?.Invoke(o, sp);
                // Os controles obrigatórios são conferidos por SecurityOptionsValidators, depois de qualquer PostConfigure
            });

        return builder;
    }

    /// <summary>Esquemas registrados (para os pacotes de provedor).</summary>
    /// <exception cref="InvalidOperationException">Sem <see cref="AddAspNetCore"/> antes.</exception>
    public static SecuritySchemes GetSchemes(this SecurityBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Properties.TryGetValue(typeof(SecuritySchemes), out object? value)
            ? (SecuritySchemes)value
            : throw new InvalidOperationException("Chame security.AddAspNetCore() antes de adicionar provedores ASP.NET Core.");
    }

    /// <summary>Opções da integração ASP.NET Core (para os pacotes de provedor).</summary>
    public static SecurityAspNetCoreOptions GetAspNetCoreOptions(this SecurityBuilder builder)
    {
        _ = GetSchemes(builder);
        return (SecurityAspNetCoreOptions)builder.Properties[typeof(SecurityAspNetCoreOptions)];
    }
}
