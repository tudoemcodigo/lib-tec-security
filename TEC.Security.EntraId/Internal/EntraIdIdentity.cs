using System.Security.Claims;
using TEC.Core.Security;
using TEC.Security.Claims;

namespace TEC.Security.EntraId.Internal;

/// <summary>Conversão dos claims do Entra ID em <see cref="ExternalIdentity"/>.</summary>
internal static class EntraIdIdentity
{
    /// <summary>
    /// Access token de API. Exige <c>tid</c> e <c>oid</c> (GUIDs), <c>scp</c> ou <c>roles</c> e <c>azp</c>/<c>appid</c>, e recusa
    /// <c>nonce</c>: um ID token apresentado como access token é recusado, mesmo com a audiência certa. Sem <c>scp</c>, só é
    /// aceito como aplicação com <c>idtyp=app</c> ou <c>sub == oid</c>.
    /// </summary>
    public static ExternalIdentity? FromAccessToken(string scheme, IReadOnlyCollection<Claim> claims, EntraIdApiOptions options, out string reason)
    {
        string? tid = Single(claims, "tid");
        string? oid = Single(claims, "oid");
        if (!EntraIdCloud.IsGuid(tid) || !EntraIdCloud.IsGuid(oid))
        {
            reason = "tid/oid ausente ou inválido";
            return null;
        }

        string? scp = Single(claims, "scp");
        string[] roles = [.. claims.Where(c => c.Type == "roles").Select(c => c.Value)];
        string[] scopes = string.IsNullOrWhiteSpace(scp) ? [] : scp.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (scopes.Length == 0 && roles.Length == 0)
        {
            reason = "token sem scp nem roles (ID token ou token sem permissão para a API)";
            return null;
        }

        // ID token: tem nonce e não tem azp/appid (só access tokens identificam a aplicação cliente)
        string? clientId = Single(claims, "azp") ?? Single(claims, "appid");
        if (claims.Any(c => c.Type == "nonce") || !EntraIdCloud.IsGuid(clientId))
        {
            reason = "token sem azp/appid ou com nonce (ID token apresentado como access token)";
            return null;
        }

        // Token delegado (usuário) tem scp. Token de aplicação não tem scp e tem idtyp=app (claim opcional) ou sub == oid
        // (o sujeito é a própria service principal); sem nenhum dos dois, não é aceito como aplicação.
        string? idtyp = Single(claims, "idtyp");
        PrincipalKind kind;
        if (scopes.Length > 0 && idtyp != "app")
            kind = PrincipalKind.User;
        else if (idtyp == "app" || string.Equals(Single(claims, "sub"), oid, StringComparison.OrdinalIgnoreCase))
            kind = PrincipalKind.Application;
        else
        {
            reason = "token sem scp que não é de aplicação (idtyp/sub)";
            return null;
        }

        if (kind == PrincipalKind.Application && !options.AllowApplicationTokens)
        {
            reason = "token de aplicação não permitido (AllowApplicationTokens = false)";
            return null;
        }

        if (options.AllowedClientApplications.Count > 0
            && (clientId is null || !options.AllowedClientApplications.Contains(clientId, StringComparer.OrdinalIgnoreCase)))
        {
            reason = "aplicação cliente fora de AllowedClientApplications";
            return null;
        }

        reason = string.Empty;
        return new ExternalIdentity
        {
            Scheme = scheme,
            Provider = EntraIdTenantPolicy.ProviderName,
            UserId = oid!.ToLowerInvariant(),
            Kind = kind,
            ExternalTenantId = tid!.ToLowerInvariant(),
            Name = kind == PrincipalKind.User ? Single(claims, "name") ?? Single(claims, "preferred_username") : clientId,
            ClientId = clientId,
            Roles = roles,
            Scopes = kind == PrincipalKind.User ? scopes : [],
            SourceClaims = claims
        };
    }

    /// <summary>ID token do login web: sempre usuário; papéis do claim <c>roles</c> (app roles atribuídos ao usuário).</summary>
    public static ExternalIdentity? FromIdToken(string scheme, IReadOnlyCollection<Claim> claims, out string reason)
    {
        string? tid = Single(claims, "tid");
        string? oid = Single(claims, "oid");
        if (!EntraIdCloud.IsGuid(tid) || !EntraIdCloud.IsGuid(oid))
        {
            reason = "tid/oid ausente ou inválido (inclua o escopo openid/profile)";
            return null;
        }

        reason = string.Empty;
        return new ExternalIdentity
        {
            Scheme = scheme,
            Provider = EntraIdTenantPolicy.ProviderName,
            UserId = oid!.ToLowerInvariant(),
            Kind = PrincipalKind.User,
            ExternalTenantId = tid!.ToLowerInvariant(),
            Name = Single(claims, "name") ?? Single(claims, "preferred_username"),
            ClientId = Single(claims, "aud"),
            Roles = [.. claims.Where(c => c.Type == "roles").Select(c => c.Value)],
            // ID token, nonce e hashes de código/token não interessam à aplicação e não vão para o cookie
            SourceClaims = [.. claims.Where(c => c.Type is not ("nonce" or "c_hash" or "at_hash" or "uti" or "rh" or "aio" or "sid"))]
        };
    }

    /// <summary>Valor do claim quando há exatamente um; vários valores do mesmo claim escalar são tratados como ausente.</summary>
    private static string? Single(IReadOnlyCollection<Claim> claims, string type)
    {
        string? found = null;
        foreach (var claim in claims)
        {
            if (claim.Type != type)
                continue;
            if (found is not null)
                return null;
            found = claim.Value;
        }

        return found;
    }
}
