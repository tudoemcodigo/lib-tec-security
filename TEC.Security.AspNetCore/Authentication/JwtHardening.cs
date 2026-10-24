using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using TEC.Security.Claims;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Padrões endurecidos de validação de JWT, aplicados a todo provedor bearer, e conferência dos controles obrigatórios depois
/// da configuração do provedor (um provedor não consegue desligá-los).
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><description>Emissor, audiência, validade e assinatura sempre validados; token sem <c>exp</c> ou sem assinatura recusado.</description></item>
/// <item><description>Algoritmos explícitos (padrão RS256, PS256, ES256): <c>alg: none</c> e confusão HS256 com chave pública impossíveis.</description></item>
/// <item><description>Chaves somente do JWKS do emissor configurado: <c>jku</c>, <c>x5u</c> e <c>jwk</c> do cabeçalho são ignorados pela biblioteca.</description></item>
/// <item><description>Tolerância de relógio de 30 segundos (o padrão do .NET é 5 minutos).</description></item>
/// <item><description><c>MapInboundClaims = false</c> (claims com os nomes originais, sem a tradução para URIs do WS-Fed),
/// <c>SaveToken = false</c> (o token não fica nas <c>AuthenticationProperties</c>), metadados só por HTTPS.</description></item>
/// <item><description>Tamanho máximo do token e intervalo mínimo entre recargas do JWKS (proteção contra DoS com <c>kid</c> desconhecido).</description></item>
/// <item><description>Detalhes do erro (<c>error_description</c> no <c>WWW-Authenticate</c>) só em Development.</description></item>
/// </list>
/// </remarks>
public static class JwtHardening
{
    /// <summary>Tolerância de relógio padrão.</summary>
    public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromSeconds(30);

    /// <summary>Tolerância máxima aceita.</summary>
    public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(2);

    /// <summary>Algoritmos padrão (assimétricos).</summary>
    public static readonly IReadOnlyList<string> DefaultAlgorithms =
        [SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.EcdsaSha256];

    /// <summary>Algoritmos assimétricos aceitos (nomes JWS e os URIs equivalentes do XML DSig).</summary>
    private static readonly HashSet<string> AsymmetricAlgorithms = new(StringComparer.Ordinal)
    {
        SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
        SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.RsaSha384Signature, SecurityAlgorithms.RsaSha512Signature,
        SecurityAlgorithms.RsaSsaPssSha256Signature, SecurityAlgorithms.RsaSsaPssSha384Signature, SecurityAlgorithms.RsaSsaPssSha512Signature,
        SecurityAlgorithms.EcdsaSha256Signature, SecurityAlgorithms.EcdsaSha384Signature, SecurityAlgorithms.EcdsaSha512Signature
    };

    /// <summary>Algoritmos HMAC (só com <c>allowSymmetricKeys</c>).</summary>
    private static readonly HashSet<string> SymmetricAlgorithms = new(StringComparer.Ordinal)
    {
        SecurityAlgorithms.HmacSha256, SecurityAlgorithms.HmacSha384, SecurityAlgorithms.HmacSha512,
        SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.HmacSha384Signature, SecurityAlgorithms.HmacSha512Signature
    };

    /// <summary>
    /// Lista de algoritmos não vazia e só com algoritmos conhecidos (lista de permissão, não de bloqueio): <c>none</c>, nomes
    /// desconhecidos e, sem <paramref name="allowSymmetricKeys"/>, HMAC em qualquer grafia (<c>HS256</c> ou o URI
    /// <c>...#hmac-sha256</c>) são recusados.
    /// </summary>
    internal static bool AreAllowedAlgorithms(IEnumerable<string>? algorithms, bool allowSymmetricKeys)
    {
        if (algorithms is null)
            return false;

        bool any = false;
        foreach (string algorithm in algorithms)
        {
            any = true;
            if (algorithm is null || !(AsymmetricAlgorithms.Contains(algorithm) || (allowSymmetricKeys && SymmetricAlgorithms.Contains(algorithm))))
                return false;
        }

        return any;
    }

    /// <summary>Aplica os padrões (antes da configuração do provedor).</summary>
    public static void ApplyDefaults(JwtBearerOptions options, int maxTokenLength, bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.MapInboundClaims = false;
        options.SaveToken = false;
        options.RequireHttpsMetadata = true;
        options.IncludeErrorDetails = isDevelopment;
        options.RefreshOnIssuerKeyNotFound = true;
        options.AutomaticRefreshInterval = TimeSpan.FromHours(12);
        options.RefreshInterval = TimeSpan.FromMinutes(5);

        options.TokenHandlers.Clear();
        options.TokenHandlers.Add(new JsonWebTokenHandler { MapInboundClaims = false, MaximumTokenSizeInBytes = maxTokenLength });

        var parameters = options.TokenValidationParameters;
        parameters.ValidateIssuer = true;
        parameters.ValidateAudience = true;
        parameters.ValidateLifetime = true;
        parameters.ValidateIssuerSigningKey = true;
        parameters.RequireExpirationTime = true;
        parameters.RequireSignedTokens = true;
        parameters.RequireAudience = true;
        parameters.TryAllIssuerSigningKeys = false;
        parameters.ClockSkew = DefaultClockSkew;
        parameters.ValidAlgorithms = [.. DefaultAlgorithms];
        parameters.NameClaimType = TecClaimTypes.Name;
        parameters.RoleClaimType = TecClaimTypes.Role;
        parameters.SaveSigninToken = false;
    }

    /// <summary>Teto do tamanho do token aceito pelo handler (o mesmo de <c>SecurityAspNetCoreOptions.MaxTokenLength</c>).</summary>
    private const int MaxTokenSizeInBytes = 256 * 1024;

    /// <summary>
    /// Confere os controles obrigatórios depois da configuração do provedor.
    /// </summary>
    /// <remarks>
    /// Além das validações e dos algoritmos, recusa ganchos que trocariam a origem das chaves ou a leitura do token:
    /// <c>IssuerSigningKeyResolver</c>, <c>IssuerSigningKeyValidator</c>, <c>TokenReader</c>, chaves de decifração (JWE),
    /// <c>UseSecurityTokenValidators</c> e <c>TokenHandlers</c> diferente de um único <see cref="JsonWebTokenHandler"/> com
    /// <c>MapInboundClaims = false</c> e tamanho máximo.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Algum controle foi desligado ou falta configuração essencial.</exception>
    public static void Enforce(JwtBearerOptions options, string scheme, bool allowSymmetricKeys = false) =>
        Enforce(options, scheme, allowSymmetricKeys, MaxTokenSizeInBytes, allowedSigningKeyValidator: null);

    /// <summary>
    /// Confere os controles obrigatórios; <paramref name="allowedSigningKeyValidator"/> é a única conferência de chave aceita (a
    /// do próprio provedor, ver <see cref="JwtProviderDefinition.SigningKeyValidator"/>).
    /// </summary>
    internal static void Enforce(JwtBearerOptions options, string scheme, bool allowSymmetricKeys, int maxTokenLength,
        IssuerSigningKeyValidatorUsingConfiguration? allowedSigningKeyValidator)
    {
        ArgumentNullException.ThrowIfNull(options);
        var p = options.TokenValidationParameters;

        void Require(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException($"Esquema '{scheme}': {message}");
        }

        Require(p.ValidateIssuer && p.ValidateAudience && p.ValidateLifetime && p.ValidateIssuerSigningKey,
            "validação de emissor, audiência, validade e chave de assinatura não pode ser desligada.");
        Require(p.RequireExpirationTime && p.RequireSignedTokens && p.RequireAudience,
            "tokens sem expiração, sem assinatura ou sem audiência não podem ser aceitos.");
        Require(p.SignatureValidator is null && p.SignatureValidatorUsingConfiguration is null,
            "SignatureValidator personalizado não é permitido (desligaria a verificação de assinatura).");
        Require(p.LifetimeValidator is null, "LifetimeValidator personalizado não é permitido.");
        Require(p.ClockSkew >= TimeSpan.Zero && p.ClockSkew <= MaxClockSkew, "ClockSkew deve ficar entre 0 e 2 minutos.");
        Require(!options.MapInboundClaims && !options.SaveToken, "MapInboundClaims e SaveToken devem ficar desligados.");
        Require(options.RequireHttpsMetadata || IsLoopback(options.Authority),
            "metadados e chaves de assinatura (JWKS) só podem ser obtidos por HTTPS (RequireHttpsMetadata).");
        Require(p.AudienceValidator is null, "AudienceValidator personalizado não é permitido (informe ValidAudiences).");
        Require(p.ValidAudience is not null || p.ValidAudiences?.Any() == true,
            "informe as audiências aceitas.");
        Require(p.IssuerValidator is null && p.IssuerValidatorUsingConfiguration is null,
            "IssuerValidator personalizado não é permitido (informe ValidIssuers).");
        Require(p.ValidIssuer is not null || p.ValidIssuers?.Any() == true,
            "informe o emissor aceito.");
        Require(p.AlgorithmValidator is null, "AlgorithmValidator personalizado não é permitido (use ValidAlgorithms).");
        Require(p.IssuerSigningKeyResolver is null && p.IssuerSigningKeyResolverUsingConfiguration is null,
            "IssuerSigningKeyResolver personalizado não é permitido (chaves só do JWKS do emissor configurado).");
        Require(p.IssuerSigningKeyValidator is null
            && (p.IssuerSigningKeyValidatorUsingConfiguration is null || p.IssuerSigningKeyValidatorUsingConfiguration == allowedSigningKeyValidator),
            "IssuerSigningKeyValidator personalizado não é permitido (desligaria a conferência da chave de assinatura).");
        Require(p.TokenReader is null, "TokenReader personalizado não é permitido.");
        Require(p.TokenDecryptionKeyResolver is null && p.TokenDecryptionKey is null && p.TokenDecryptionKeys?.Any() != true,
            "tokens cifrados (JWE) não são suportados: remova as chaves de decifração.");
        Require(p.TransformBeforeSignatureValidation is null, "TransformBeforeSignatureValidation não é permitido.");
        Require(p.CryptoProviderFactory is null, "CryptoProviderFactory personalizada não é permitida.");
        Require(!options.UseSecurityTokenValidators && options.TokenHandlers.Count == 1
            && options.TokenHandlers[0] is JsonWebTokenHandler { MapInboundClaims: false } handler
            && handler.MaximumTokenSizeInBytes > 0 && handler.MaximumTokenSizeInBytes <= maxTokenLength,
            "TokenHandlers não pode ser substituído (um JsonWebTokenHandler com MapInboundClaims = false e o tamanho máximo do token).");
        Require(AreAllowedAlgorithms(p.ValidAlgorithms, allowSymmetricKeys),
            allowSymmetricKeys
                ? "informe os algoritmos aceitos (ValidAlgorithms): RS*, PS*, ES* ou HS*; 'none' não é permitido."
                : "informe os algoritmos aceitos (ValidAlgorithms) só entre RS*, PS* e ES*: 'none' e HMAC (HS256...) não são permitidos para provedores externos.");
    }

    private static bool IsLoopback(string? authority)
    {
        if (string.IsNullOrWhiteSpace(authority))
            return false;
        if (Uri.TryCreate(authority, UriKind.Absolute, out var uri))
            return uri.IsLoopback;
        return false;
    }
}
