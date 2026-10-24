using System.Security.Cryptography;
using System.Text;
using TEC.Core.Text.Codecs;
using TEC.Security.Common;

namespace TEC.Security.ApiKeys;

/// <summary>API key recém-gerada: a chave (entregue uma única vez ao sistema cliente) e o hash (vai para a configuração).</summary>
/// <remarks><see cref="ToString"/> não mostra a chave.</remarks>
public sealed class GeneratedApiKey
{
    internal GeneratedApiKey(string keyId, string key, string hash)
    {
        KeyId = keyId;
        Key = key;
        Hash = hash;
    }

    /// <summary>Id da chave (chave em <c>Security:ApiKeys:Keys</c>).</summary>
    public string KeyId { get; }

    /// <summary>Chave completa (<c>tec_{id}_{segredo}</c>). Entregue ao cliente por canal seguro e <b>não</b> guarde.</summary>
    public string Key { get; }

    /// <summary>Hash do segredo para <c>Security:ApiKeys:Keys:{id}:Hash</c>.</summary>
    public string Hash { get; }

    /// <inheritdoc />
    public override string ToString() => $"GeneratedApiKey {{ KeyId = {KeyId}, Hash = {Hash}, Key = *** }}";
}

/// <summary>
/// Gera API keys com 256 bits aleatórios e calcula o hash guardado na configuração.
/// </summary>
/// <remarks>
/// <para>Formato: <c>tec_{id}_{segredo}</c>. O id (público) localiza o cadastro; o segredo (32 bytes de
/// <see cref="RandomNumberGenerator"/>, Base64Url canônico do <see cref="Base64UrlEncoder"/>) nunca é guardado: só o SHA-256
/// dele. Por ter 256 bits de entropia, um hash rápido é suficiente (não há dicionário possível), e a comparação é em tempo
/// constante.</para>
/// <para>O prefixo <c>tec_</c> permite que ferramentas de varredura de segredos (ex.: GitHub secret scanning com padrão
/// personalizado) encontrem chaves vazadas em repositórios.</para>
/// </remarks>
/// <example>
/// <code>
/// var nova = ApiKeyGenerator.Generate("erp-contoso");
/// // nova.Key  -> entregar ao ERP (uma única vez)
/// // nova.Hash -> "Security:ApiKeys:Keys:erp-contoso:Hash"
/// </code>
/// </example>
public static class ApiKeyGenerator
{
    /// <summary>Prefixo das chaves.</summary>
    public const string Prefix = "tec_";

    /// <summary>Bytes aleatórios do segredo.</summary>
    public const int SecretBytes = 32;

    /// <summary>Tamanho máximo aceito de uma chave apresentada (evita processar entradas enormes).</summary>
    public const int MaxKeyLength = 128;

    /// <summary>Tamanho, em caracteres Base64Url, do segredo e do hash (32 bytes sem preenchimento).</summary>
    private const int EncodedLength = 43;

    /// <summary>Gera uma nova chave para o id informado.</summary>
    /// <param name="keyId">Id público da chave (minúsculas, dígitos e hífen, 3 a 40 caracteres).</param>
    /// <returns>A chave completa (entregue uma única vez) e o hash a cadastrar.</returns>
    /// <exception cref="ArgumentException">Id fora do formato (minúsculas, dígitos e hífen, 3 a 40 caracteres).</exception>
    public static GeneratedApiKey Generate(string keyId)
    {
        if (!SecurityRules.IsValidServiceName(keyId))
            throw new ArgumentException("Id de API key inválido: use minúsculas, dígitos e hífen (3 a 40 caracteres).", nameof(keyId));

        Span<byte> random = stackalloc byte[SecretBytes];
        RandomNumberGenerator.Fill(random);
        string secret = Base64UrlEncoder.Encode(random);
        CryptographicOperations.ZeroMemory(random);

        return new GeneratedApiKey(keyId, $"{Prefix}{keyId}_{secret}", ComputeHash(secret));
    }

    /// <summary>Hash (SHA-256, Base64Url) do segredo de uma chave.</summary>
    /// <param name="secret">Segredo (parte da chave depois do id).</param>
    /// <returns>SHA-256 do segredo em Base64Url sem preenchimento (43 caracteres).</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> nulo.</exception>
    public static string ComputeHash(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        byte[] bytes = Encoding.UTF8.GetBytes(secret);
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        try
        {
            SHA256.HashData(bytes, hash);
            return Base64UrlEncoder.Encode(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    /// <summary>
    /// Separa id e segredo de uma chave apresentada; <c>false</c> fora do formato. O segredo precisa ser Base64Url canônico
    /// (32 bytes): variações de uma mesma chave (bits finais diferentes) são recusadas.
    /// </summary>
    internal static bool TryParse(string? presented, out string keyId, out string secret)
    {
        keyId = secret = string.Empty;
        if (presented is null || presented.Length > MaxKeyLength || !presented.StartsWith(Prefix, StringComparison.Ordinal))
            return false;

        int separator = presented.IndexOf('_', Prefix.Length);
        if (separator < 0)
            return false;

        string id = presented[Prefix.Length..separator];
        string value = presented[(separator + 1)..];
        if (!SecurityRules.IsValidServiceName(id) || value.Length != EncodedLength || !Base64UrlEncoder.IsValid(value))
            return false;

        keyId = id;
        secret = value;
        return true;
    }

    /// <summary>Decodifica um hash Base64Url canônico de 32 bytes; <c>null</c> se inválido.</summary>
    internal static byte[]? DecodeHash(string? hash) =>
        hash is { Length: EncodedLength } && Base64UrlEncoder.TryDecode(hash, out byte[] bytes) && bytes.Length == SHA256.HashSizeInBytes
            ? bytes
            : null;
}
