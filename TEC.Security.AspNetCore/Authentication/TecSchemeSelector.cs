using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Escolhe o esquema de cada requisição (seletor do policy scheme <see cref="SecurityAspNetCoreOptions.DefaultScheme"/>).
/// </summary>
/// <remarks>
/// <para>Ordem: header <c>Authorization: Bearer</c> → provedor cujo <see cref="BearerProviderRegistration.CanHandle"/> aceita o
/// token; header de API key → esquema de API key; <c>access_token</c> na query (só em <see cref="SecurityAspNetCoreOptions.HubPaths"/>)
/// → como bearer; senão → cookie do login web, se houver. Sem correspondência → <see cref="SecurityAspNetCoreOptions.NoCredentialsScheme"/>,
/// que recusa credenciais desconhecidas (outro tipo de header Authorization, emissor não registrado, token malformado).</para>
/// <para>O token é lido <b>sem validação</b> apenas para escolher o esquema; nenhuma informação dele é usada antes da validação
/// completa feita pelo esquema escolhido.</para>
/// </remarks>
internal sealed class TecSchemeSelector(SecuritySchemes schemes, SecurityAspNetCoreOptions options, ApiKeys.ApiKeyValidator apiKeys)
{
    private readonly JsonWebTokenHandler _reader = new() { MaximumTokenSizeInBytes = options.MaxTokenLength };

    public string Select(HttpContext context)
    {
        var request = context.Request;

        if (request.Headers.Authorization.Count > 0)
            return TryGetBearer(request.Headers.Authorization, out string? token) ? SelectBearer(token) : SecurityAspNetCoreOptions.NoCredentialsScheme;

        if (schemes.ApiKeyScheme is { } apiKeyScheme && request.Headers.ContainsKey(apiKeys.HeaderName))
            return apiKeyScheme;

        if (TryGetHubToken(request, options, out string? hubToken))
            return SelectBearer(hubToken);

        return schemes.CookieScheme ?? SecurityAspNetCoreOptions.NoCredentialsScheme;
    }

    /// <summary>Exatamente um header <c>Authorization: Bearer &lt;token&gt;</c>.</summary>
    internal static bool TryGetBearer(StringValues header, out string token)
    {
        token = string.Empty;
        if (header.Count != 1 || header[0] is not { } value)
            return false;

        const string prefix = "Bearer ";
        if (!value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        token = value[prefix.Length..].Trim();
        return token.Length > 0;
    }

    /// <summary><c>access_token</c> da query, só para os caminhos de hub configurados.</summary>
    internal static bool TryGetHubToken(HttpRequest request, SecurityAspNetCoreOptions options, out string token)
    {
        token = string.Empty;
        if (options.HubPaths.Count == 0 || !options.HubPaths.Any(p => request.Path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase)))
            return false;

        var values = request.Query["access_token"];
        if (values.Count != 1 || string.IsNullOrWhiteSpace(values[0]))
            return false;

        token = values[0]!;
        return true;
    }

    private string SelectBearer(string token)
    {
        if (schemes.Bearer.Count == 0 || token.Length > options.MaxTokenLength || !_reader.CanReadToken(token))
            return SecurityAspNetCoreOptions.NoCredentialsScheme;

        JsonWebToken jwt;
        try
        {
            jwt = _reader.ReadJsonWebToken(token);
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException or System.Text.Json.JsonException
                                              or Microsoft.IdentityModel.Tokens.SecurityTokenException)
        {
            return SecurityAspNetCoreOptions.NoCredentialsScheme;
        }

        foreach (var provider in schemes.Bearer)
        {
            try
            {
                if (provider.CanHandle(jwt))
                    return provider.Scheme;
            }
            catch (Exception exception) when (exception is ArgumentException or FormatException or InvalidOperationException
                                                  or System.Text.Json.JsonException)
            {
                // Claim com tipo inesperado: este provedor não reconhece o token
            }
        }

        return SecurityAspNetCoreOptions.NoCredentialsScheme;
    }
}
