using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using TEC.Security.Claims;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Definição de um provedor de tokens bearer (JWT) para <c>AddJwtBearerProvider</c>. Uso pelos pacotes de provedor
/// (Entra ID, Keycloak...): o pacote informa como reconhecer o token e como convertê-lo em <see cref="ExternalIdentity"/>; a
/// validação endurecida, a normalização e os eventos ficam a cargo do TEC.Security.
/// </summary>
public sealed class JwtProviderDefinition
{
    /// <summary>Nome do esquema (ex.: <c>Funcionarios</c>). Único na aplicação.</summary>
    public required string Scheme { get; init; }

    /// <summary>Tipo do provedor (ex.: <c>EntraId</c>); chave em <c>Security:Tenants:*:IdentityProviders</c>.</summary>
    public required string Provider { get; init; }

    /// <summary>Reconhece o token (lido sem validação) pelo emissor/audiência. Ver <see cref="BearerProviderRegistration.CanHandle"/>.</summary>
    public required Func<JsonWebToken, bool> CanHandle { get; init; }

    /// <summary>
    /// Converte o token <b>já validado</b> (<see cref="TokenValidatedContext.SecurityToken"/>, um <see cref="JsonWebToken"/>) em
    /// identidade. Retorne <c>null</c> com o motivo em <c>reason</c> para recusar (ex.: claim obrigatório ausente).
    /// </summary>
    public required CreateIdentityDelegate CreateIdentity { get; init; }

    /// <summary>
    /// Configuração específica do provedor (authority, audiências, emissor, algoritmos). Aplicada depois dos padrões
    /// endurecidos; os controles obrigatórios são conferidos de novo depois dela (ver <c>JwtHardening</c>).
    /// </summary>
    public Action<JwtBearerOptions, IServiceProvider>? Configure { get; init; }
}

/// <summary>Converte um token validado em identidade, ou recusa com o motivo (sem dados do token).</summary>
public delegate ExternalIdentity? CreateIdentityDelegate(TokenValidatedContext context, JsonWebToken token, out string reason);
