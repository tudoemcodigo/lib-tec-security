namespace TEC.Security.Abstractions;

/// <summary>Token de acesso obtido para chamar outro serviço.</summary>
/// <remarks><see cref="ToString"/> não mostra o token.</remarks>
public sealed class AccessToken(string token, DateTimeOffset expiresOn)
{
    /// <summary>Valor do token (bearer). Nunca registre em log.</summary>
    public string Token { get; } = string.IsNullOrWhiteSpace(token)
        ? throw new ArgumentException("O token não pode ser vazio.", nameof(token))
        : token;

    /// <summary>Expiração.</summary>
    public DateTimeOffset ExpiresOn { get; } = expiresOn;

    /// <inheritdoc />
    public override string ToString() => $"AccessToken {{ ExpiresOn = {ExpiresOn:O}, Token = *** }}";
}

/// <summary>
/// Obtém tokens de acesso da própria aplicação (client credentials, identidade gerenciada) para chamar outros serviços.
/// Implementado pelos pacotes de provedor (ex.: <c>TEC.Security.EntraId</c>) e usado pelo <c>AccessTokenHandler</c> do
/// <c>HttpClient</c>.
/// </summary>
public interface IAccessTokenProvider
{
    /// <summary>Token para os escopos informados (ex.: <c>api://minha-api/.default</c>). Implementações mantêm cache até perto da expiração.</summary>
    ValueTask<AccessToken> GetTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken);
}
