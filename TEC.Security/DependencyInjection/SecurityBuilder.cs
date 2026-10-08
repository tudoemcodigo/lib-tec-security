using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using TEC.Security.Abstractions;

namespace TEC.Security.DependencyInjection;

/// <summary>Configuração do <c>AddTecSecurity</c>: fontes de permissões e tenants e ponto de extensão dos pacotes de provedor.</summary>
public sealed class SecurityBuilder
{
    internal SecurityBuilder(IServiceCollection services, IConfiguration configuration)
    {
        Services = services;
        Configuration = configuration;
    }

    /// <summary>Container, para os pacotes de provedor registrarem as suas dependências.</summary>
    public IServiceCollection Services { get; }

    /// <summary>Configuração da aplicação (seções <c>Security:*</c>).</summary>
    public IConfiguration Configuration { get; }

    /// <summary>
    /// Estado dos pacotes de extensão (ex.: esquemas registrados pelo <c>TEC.Security.AspNetCore</c>), por tipo. Uso pelos
    /// pacotes de provedor.
    /// </summary>
    public IDictionary<Type, object> Properties { get; } = new Dictionary<Type, object>();

    internal Type? PermissionStoreType { get; private set; }

    internal TimeSpan? PermissionCacheDuration { get; private set; }

    internal Type? TenantRegistryType { get; private set; }

    /// <summary>
    /// Usa <typeparamref name="TStore"/> (ex.: consulta ao banco) como fonte das permissões, com cache de
    /// <paramref name="cacheDuration"/> (padrão: 5 minutos; <see cref="TimeSpan.Zero"/> desliga o cache). Substitui o
    /// mapeamento de <c>Security:Permissions</c>.
    /// </summary>
    /// <remarks><typeparamref name="TStore"/> é registrado como Singleton: dependências Scoped (ex.: DbContext) devem ser obtidas
    /// por <c>IServiceScopeFactory</c> dentro do método.</remarks>
    /// <param name="cacheDuration">Duração do cache (padrão: 5 minutos; <see cref="TimeSpan.Zero"/> desliga; máximo 1 hora).</param>
    /// <returns>O próprio builder.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Duração fora de 0 a 1 hora.</exception>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez.</exception>
    public SecurityBuilder UsePermissionStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        TimeSpan? cacheDuration = null)
        where TStore : class, IPermissionStore
    {
        var duration = cacheDuration ?? TimeSpan.FromMinutes(5);
        if (duration < TimeSpan.Zero || duration > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(cacheDuration), "O cache de permissões deve ficar entre 0 e 1 hora.");
        if (PermissionStoreType is not null)
            throw new InvalidOperationException("UsePermissionStore já foi chamado: registre uma única fonte de permissões.");

        Services.AddSingleton<TStore>();
        PermissionStoreType = typeof(TStore);
        PermissionCacheDuration = duration == TimeSpan.Zero ? null : duration;
        return this;
    }

    /// <summary>
    /// Usa <typeparamref name="TRegistry"/> como cadastro de tenants (ex.: tabela do banco mantida em memória), no lugar de
    /// <c>Security:Tenants</c>. Registrado como Singleton.
    /// </summary>
    /// <returns>O próprio builder.</returns>
    /// <exception cref="InvalidOperationException">Chamado mais de uma vez.</exception>
    public SecurityBuilder UseTenantRegistry<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TRegistry>()
        where TRegistry : class, ITenantRegistry
    {
        if (TenantRegistryType is not null)
            throw new InvalidOperationException("UseTenantRegistry já foi chamado: registre um único cadastro de tenants.");
        Services.AddSingleton<TRegistry>();
        TenantRegistryType = typeof(TRegistry);
        return this;
    }
}
