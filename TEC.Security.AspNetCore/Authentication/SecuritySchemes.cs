using Microsoft.IdentityModel.JsonWebTokens;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>Provedor de tokens bearer registrado (uso pelos pacotes de provedor).</summary>
/// <param name="Scheme">Nome do esquema JwtBearer.</param>
/// <param name="Provider">Tipo do provedor (ex.: <c>EntraId</c>).</param>
/// <param name="CanHandle">
/// Decide se o token (lido <b>sem validação</b>) é deste provedor, normalmente pelo emissor. Só escolhe o esquema: o token
/// é validado por inteiro pelo esquema escolhido, então um valor adulterado leva no máximo a uma recusa.
/// </param>
public sealed record BearerProviderRegistration(string Scheme, string Provider, Func<JsonWebToken, bool> CanHandle);

/// <summary>Esquemas registrados, consultados pelo seletor de esquema a cada requisição. Singleton.</summary>
public sealed class SecuritySchemes
{
    private readonly List<BearerProviderRegistration> _bearer = [];

    /// <summary>Provedores de token bearer, na ordem de registro.</summary>
    public IReadOnlyList<BearerProviderRegistration> Bearer => _bearer;

    /// <summary>Esquema de cookie do login web (ou <c>null</c>).</summary>
    public string? CookieScheme { get; private set; }

    /// <summary>Esquema de API key (ou <c>null</c>).</summary>
    public string? ApiKeyScheme { get; private set; }

    /// <summary>Todos os esquemas registrados pelo TEC.Security.</summary>
    public IEnumerable<string> All =>
        _bearer.Select(b => b.Scheme)
            .Concat(CookieScheme is null ? [] : [CookieScheme])
            .Concat(ApiKeyScheme is null ? [] : [ApiKeyScheme]);

    internal void AddBearer(BearerProviderRegistration registration)
    {
        EnsureUnique(registration.Scheme);
        _bearer.Add(registration);
    }

    internal void SetCookie(string scheme)
    {
        if (CookieScheme is not null)
            throw new InvalidOperationException("Só um login web (cookie) é suportado por aplicação.");
        EnsureUnique(scheme);
        CookieScheme = scheme;
    }

    internal void SetApiKey(string scheme)
    {
        if (ApiKeyScheme is not null)
            throw new InvalidOperationException("AddApiKeys já foi chamado.");
        EnsureUnique(scheme);
        ApiKeyScheme = scheme;
    }

    private void EnsureUnique(string scheme)
    {
        if (string.IsNullOrWhiteSpace(scheme) || !Common.SecurityRules.IsValidName(scheme))
            throw new ArgumentException("Nome de esquema inválido (letras, dígitos e _ . : / -).", nameof(scheme));

        if (All.Contains(scheme, StringComparer.OrdinalIgnoreCase)
            || scheme.Equals(SecurityAspNetCoreOptions.DefaultScheme, StringComparison.OrdinalIgnoreCase)
            || scheme.Equals(SecurityAspNetCoreOptions.NoCredentialsScheme, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"O esquema '{scheme}' já está registrado ou é reservado.");
    }
}
