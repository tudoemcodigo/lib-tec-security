using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using TEC.Security.Claims;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Definição de um login web (OpenID Connect + cookie de sessão) para <c>AddWebLoginProvider</c>. Uso pelos pacotes de
/// provedor: o pacote configura o OIDC e converte o ID token em <see cref="ExternalIdentity"/>; o endurecimento do OIDC e do
/// cookie, a normalização e a revalidação periódica da sessão ficam a cargo do TEC.Security.
/// </summary>
public sealed class WebLoginDefinition
{
    /// <summary>Nome do esquema do cookie (ex.: <c>Web</c>). O esquema OIDC se chama <c>{Scheme}.oidc</c>.</summary>
    public required string Scheme { get; init; }

    /// <summary>Tipo do provedor (ex.: <c>EntraId</c>).</summary>
    public required string Provider { get; init; }

    /// <summary>Converte o ID token já validado em identidade, ou recusa com o motivo.</summary>
    public required CreateWebIdentityDelegate CreateIdentity { get; init; }

    /// <summary>Configuração específica do provedor (authority, client id, emissor, credencial do cliente).</summary>
    public Action<OpenIdConnectOptions, IServiceProvider>? Configure { get; init; }

    /// <summary>Ajustes no cookie depois dos padrões (ex.: <c>ExpireTimeSpan</c>). Os controles obrigatórios são conferidos depois.</summary>
    public Action<CookieAuthenticationOptions>? ConfigureCookie { get; init; }

    /// <summary>
    /// Intervalo de revalidação da sessão (tenant e permissões consultados de novo). Padrão: 5 minutos (1 minuto a 1 hora).
    /// O tenant ativo é conferido em <b>toda</b> requisição, independentemente deste intervalo.
    /// </summary>
    public TimeSpan RevalidationInterval { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Duração máxima absoluta da sessão desde o login, independentemente do uso (a expiração deslizante do cookie não a
    /// estende). Depois dela, o usuário passa pelo provedor de novo, que confere conta desativada e papéis removidos. Padrão:
    /// 8 horas (1 a 24 horas).
    /// </summary>
    public TimeSpan MaxSessionLifetime { get; init; } = TimeSpan.FromHours(8);

    /// <summary>
    /// Regra do provedor conferida a cada revalidação (ex.: tenant do Entra ID ainda liberado). <c>false</c> encerra a sessão.
    /// </summary>
    public Func<Abstractions.ISecurityUser, IServiceProvider, bool>? IsSessionAllowed { get; init; }

    /// <summary>Nome do esquema OIDC.</summary>
    public string ChallengeScheme => Scheme + ".oidc";
}

/// <summary>Converte o ID token validado (claims de <paramref name="context"/>.Principal) em identidade, ou recusa com o motivo.</summary>
public delegate ExternalIdentity? CreateWebIdentityDelegate(TokenValidatedContext context, out string reason);
