using System.Diagnostics.CodeAnalysis;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using TEC.Security.Abstractions;

namespace TEC.Security.EntraId.Internal;

/// <summary>Nuvem do Entra ID: host de login (v2.0) e host do emissor v1.0.</summary>
internal sealed record EntraIdCloud(string LoginHost, string? V1IssuerHost)
{
    private static readonly EntraIdCloud[] Known =
    [
        new("login.microsoftonline.com", "sts.windows.net"),
        new("login.microsoftonline.us", null),
        new("login.chinacloudapi.cn", "sts.chinacloudapi.cn"),
        new("login.partner.microsoftonline.cn", "sts.chinacloudapi.cn")
    ];

    public Uri AuthorityHost => new($"https://{LoginHost}/");

    /// <summary>
    /// Nuvem da instância informada: só HTTPS, host oficial, sem porta, usuário, query ou caminho (o token e a client assertion
    /// nunca vão para outro servidor por configuração adulterada).
    /// </summary>
    public static bool TryParse(string? instance, [NotNullWhen(true)] out EntraIdCloud? cloud)
    {
        cloud = null;
        if (!Uri.TryCreate(instance, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || !uri.IsDefaultPort
            || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)
            || uri.AbsolutePath != "/")
            return false;

        cloud = Known.FirstOrDefault(k => string.Equals(k.LoginHost, uri.Host, StringComparison.OrdinalIgnoreCase));
        return cloud is not null;
    }

    public string V2Issuer(string tenantId) => $"https://{LoginHost}/{tenantId}/v2.0";

    public string? V1Issuer(string tenantId) => V1IssuerHost is null ? null : $"https://{V1IssuerHost}/{tenantId}/";

    public string Authority(string tenantSegment) => $"https://{LoginHost}/{tenantSegment}/v2.0";

    public string TokenEndpoint(string tenantSegment) => $"https://{LoginHost}/{tenantSegment}/oauth2/v2.0/token";

    public static bool IsGuid(string? value) => value is not null && Guid.TryParseExact(value, "D", out _);
}

/// <summary>Regras de emissor e tenant de uma app registration: quais tenants são aceitos e qual emissor cada um deve ter.</summary>
internal sealed class EntraIdTenantPolicy(EntraIdCloud cloud, EntraIdAppOptions options, bool acceptV1, ITenantRegistry? registry)
{
    public const string ProviderName = "EntraId";

    private readonly HashSet<string> _static = new(
        options.AllowedTenantIds.Concat(options.TenantId is null ? [] : [options.TenantId]), StringComparer.OrdinalIgnoreCase);

    public EntraIdCloud Cloud => cloud;

    /// <summary>Tenant aceito agora (cadastro relido a cada token: ativar/desativar vale sem reinício).</summary>
    public bool IsTenantAllowed(string? tenantId)
    {
        if (!EntraIdCloud.IsGuid(tenantId))
            return false;

        if (_static.Contains(tenantId!))
            return true;

        return options.MultiTenant && registry?.GetEnabledExternalIds(ProviderName).Contains(tenantId!) == true;
    }

    /// <summary>Emissor esperado para o tenant e a versão do token, ou <c>null</c> se a versão não é aceita.</summary>
    public string? ExpectedIssuer(string tenantId, string? version) => version switch
    {
        "2.0" => cloud.V2Issuer(tenantId),
        "1.0" when acceptV1 => cloud.V1Issuer(tenantId),
        _ => null
    };

    /// <summary>Validador de emissor: <c>tid</c> aceito e emissor exatamente igual ao do tenant na versão do token.</summary>
    public string ValidateIssuer(string issuer, SecurityToken token, TokenValidationParameters parameters)
    {
        if (token is JsonWebToken jwt && jwt.TryGetPayloadValue("tid", out string? tid) && IsTenantAllowed(tid)
            && jwt.TryGetPayloadValue("ver", out string? version) && ExpectedIssuer(tid!, version) is { } expected
            && string.Equals(issuer, expected, StringComparison.Ordinal))
            return issuer;

        throw new SecurityTokenInvalidIssuerException("Emissor ou tenant não aceito.");
    }

    /// <summary>Reconhecimento rápido (sem validação) para a escolha do esquema.</summary>
    public bool LooksLikeIssuer(JsonWebToken jwt) =>
        jwt.TryGetPayloadValue("tid", out string? tid) && EntraIdCloud.IsGuid(tid)
        && jwt.TryGetPayloadValue("ver", out string? version) && ExpectedIssuer(tid!, version) is { } expected
        && string.Equals(jwt.Issuer, expected, StringComparison.Ordinal);
}
