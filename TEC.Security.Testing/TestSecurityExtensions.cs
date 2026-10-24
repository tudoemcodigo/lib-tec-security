using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TEC.Core.Security;
using TEC.Security.AspNetCore;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.Claims;
using TEC.Security.DependencyInjection;
using JwtTokenValidatedContext = Microsoft.AspNetCore.Authentication.JwtBearer.TokenValidatedContext;

namespace TEC.Security.Testing;

/// <summary>Provedor de tokens de teste.</summary>
public static class TestSecurityExtensions
{
    /// <summary>Tipo do provedor de teste (chave em <c>Security:Tenants:*:IdentityProviders</c>).</summary>
    public const string ProviderName = "Test";

    /// <summary>Ambientes em que o provedor de teste é aceito.</summary>
    public static readonly IReadOnlyList<string> AllowedEnvironments = [Environments.Development, "Testing", "Test"];

    /// <summary>
    /// Aceita os tokens de <paramref name="issuer"/> (mesmas regras endurecidas dos provedores reais). Falha fechada: a aplicação
    /// não sobe fora dos ambientes <see cref="AllowedEnvironments"/>, então um provedor de teste esquecido no <c>Program.cs</c>
    /// nunca vale em produção.
    /// </summary>
    /// <exception cref="InvalidOperationException">Ambiente não permitido (verificado na criação das opções do esquema).</exception>
    public static SecurityBuilder AddTestJwt(this SecurityBuilder builder, TestTokenIssuer issuer, string scheme = ProviderName)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(issuer);

        // Falha já no registro quando o ambiente é conhecido (WebApplicationBuilder/HostApplicationBuilder registram a instância);
        // a mesma conferência roda de novo na criação das opções (validadas na inicialização do host)
        if (builder.Services.LastOrDefault(d => d.ServiceType == typeof(IHostEnvironment) && !d.IsKeyedService)?.ImplementationInstance
                is IHostEnvironment environment && !IsAllowed(environment.EnvironmentName))
            throw new InvalidOperationException("AddTestJwt só é permitido nos ambientes Development, Testing e Test.");

        return builder.AddJwtBearerProvider(new JwtProviderDefinition
        {
            Scheme = scheme,
            Provider = ProviderName,
            CanHandle = jwt => string.Equals(jwt.Issuer, issuer.Issuer, StringComparison.Ordinal),
            CreateIdentity = (JwtTokenValidatedContext _, JsonWebToken token, out string reason) => CreateIdentity(scheme, token, out reason),
            Configure = (o, sp) =>
            {
                string? environment = sp.GetService<IHostEnvironment>()?.EnvironmentName;
                if (!IsAllowed(environment))
                    throw new InvalidOperationException("AddTestJwt só é permitido nos ambientes Development, Testing e Test.");

                var configuration = new OpenIdConnectConfiguration { Issuer = issuer.Issuer };
                configuration.SigningKeys.Add(issuer.SigningKey);
                o.Configuration = configuration;
                o.TokenValidationParameters.ValidIssuer = issuer.Issuer;
                o.TokenValidationParameters.ValidAudience = issuer.Audience;
                o.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.RsaSha256];
            }
        });
    }

    private static bool IsAllowed(string? environment) =>
        environment is not null && AllowedEnvironments.Contains(environment, StringComparer.OrdinalIgnoreCase);

    private static ExternalIdentity? CreateIdentity(string scheme, JsonWebToken token, out string reason)
    {
        if (!token.TryGetPayloadValue("sub", out string? subject) || string.IsNullOrEmpty(subject))
        {
            reason = "sub ausente";
            return null;
        }

        token.TryGetPayloadValue("scp", out string? scp);
        token.TryGetPayloadValue("idtyp", out string? idtyp);
        token.TryGetPayloadValue("tid", out string? tid);
        token.TryGetPayloadValue("name", out string? name);

        reason = string.Empty;
        return new ExternalIdentity
        {
            Scheme = scheme,
            Provider = ProviderName,
            UserId = subject,
            Kind = idtyp == "app" ? PrincipalKind.Application : PrincipalKind.User,
            ExternalTenantId = tid,
            Name = name,
            Roles = [.. token.Claims.Where(c => c.Type == "roles").Select(c => c.Value)],
            Scopes = string.IsNullOrWhiteSpace(scp) ? [] : scp.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            SourceClaims = [.. token.Claims]
        };
    }
}
