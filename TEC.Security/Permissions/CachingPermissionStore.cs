using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using TEC.Core.Text.Codecs;
using TEC.Core.Threading;
using TEC.Security.Abstractions;
using TEC.Security.Common;

namespace TEC.Security.Permissions;

/// <summary>
/// Cache das permissões de um <see cref="IPermissionStore"/> (ex.: banco de dados), para não consultar a fonte a cada
/// requisição. Chave: provedor + esquema + tenant + identidade + tipo + papéis; uma mudança de papéis no token gera nova consulta.
/// </summary>
/// <remarks>
/// <para><see cref="IMemoryCache"/> privado (não compartilhado com a aplicação), com limite de entradas e chave de tamanho fixo
/// (SHA-256 da identidade): um volume grande de identidades diferentes, ou tokens com muitos papéis, não esgota a memória.</para>
/// <para>Uma única consulta à fonte por chave ao mesmo tempo (sem <i>cache stampede</i>): as requisições simultâneas da mesma
/// identidade esperam o mesmo resultado (<see cref="TEC.Core.Threading.SingleFlight{TKey, TValue}"/>). Quem cancela só desiste
/// da própria espera; a consulta é cancelada apenas quando todas as requisições que a aguardam desistem.</para>
/// <para>Uma permissão revogada na fonte continua valendo até <c>duration</c> (padrão 5 minutos). Falhas do store e resultados
/// acima de <see cref="SecurityRules.MaxItemsPerIdentity"/> (recusados na autenticação) não são guardados no cache.</para>
/// </remarks>
internal sealed class CachingPermissionStore : IPermissionStore, IDisposable
{
    internal const int MaxEntries = 50_000;

    private readonly IPermissionStore _inner;
    private readonly TimeSpan _duration;
    private readonly MemoryCache _cache = new(new MemoryCacheOptions { SizeLimit = MaxEntries });
    // Uma consulta por chave (TEC.Core): requisições simultâneas da mesma identidade aguardam a mesma consulta à fonte
    private readonly SingleFlight<string, IReadOnlyCollection<string>> _loading = new(StringComparer.Ordinal);

    public CachingPermissionStore(IPermissionStore inner, TimeSpan duration)
    {
        ArgumentNullException.ThrowIfNull(inner);
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(duration), "A duração do cache de permissões deve estar entre 1 tick e 1 hora.");

        _inner = inner;
        _duration = duration;
    }

    public async ValueTask<IReadOnlyCollection<string>> GetPermissionsAsync(PermissionContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        string key = CreateKey(context);
        if (_cache.TryGetValue(key, out IReadOnlyCollection<string>? cached) && cached is not null)
            return cached;

        return await _loading.RunAsync(key, (k, ct) => LoadAsync(k, context, ct), cancellationToken).ConfigureAwait(false);
    }

    private async Task<IReadOnlyCollection<string>> LoadAsync(string key, PermissionContext context, CancellationToken cancellationToken)
    {
        // Quem esperou na fila pode chegar depois de a consulta anterior gravar no cache
        if (_cache.TryGetValue(key, out IReadOnlyCollection<string>? cached) && cached is not null)
            return cached;

        var permissions = await _inner.GetPermissionsAsync(context, cancellationToken).ConfigureAwait(false);
        IReadOnlyCollection<string> copy = permissions is null ? [] : [.. permissions];
        if (copy.Count <= SecurityRules.MaxItemsPerIdentity)
            _cache.Set(key, copy, new MemoryCacheEntryOptions { Size = 1, AbsoluteExpirationRelativeToNow = _duration });
        return copy;
    }

    public void Dispose() => _cache.Dispose();

    /// <summary>
    /// Chave de tamanho fixo: SHA-256 (Base64Url) das partes separadas por um caractere que não é aceito nos valores
    /// (<c>\n</c>), com os papéis em ordem: sem ambiguidade e sem depender da ordem dos papéis no token.
    /// </summary>
    internal static string CreateKey(PermissionContext context)
    {
        string joined = string.Join('\n', [context.Provider, context.Scheme, context.TenantId ?? string.Empty, context.UserId,
            context.Kind.ToString(), .. context.Roles.Order(StringComparer.Ordinal)]);
        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.UTF8.GetBytes(joined)));
    }
}
