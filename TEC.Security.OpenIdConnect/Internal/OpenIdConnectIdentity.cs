using System.Security.Claims;
using System.Text.Json;
using TEC.Core.Security;
using TEC.Core.Text.Masking;
using TEC.Security.Abstractions;
using TEC.Security.Claims;
using TEC.Security.Common;

namespace TEC.Security.OpenIdConnect.Internal;

/// <summary>Converte claims OIDC/OAuth 2.0 padrão na identidade externa normalizada pelo TEC.Security.</summary>
internal static class OpenIdConnectIdentity
{
    public const string ProviderName = "OpenIdConnect";

    /// <summary>Access token de uma API: o tipo (<c>Kind</c>) vem das regras do esquema (<see cref="OpenIdConnectApiOptions.Kind"/>).</summary>
    public static ExternalIdentity? FromClaims(string scheme, IReadOnlyList<Claim> claims, OpenIdConnectApiOptions options,
        ITenantRegistry? tenantRegistry, out string rejectionReason) =>
        Create(scheme, claims, options, KindClassifier.Create(options, scheme), tenantRegistry, out rejectionReason);

    /// <summary>Access token de uma API, com as regras de <c>Kind</c> já conferidas no registro do esquema.</summary>
    public static ExternalIdentity? FromClaims(string scheme, IReadOnlyList<Claim> claims, OpenIdConnectApiOptions options,
        KindClassifier classifier, ITenantRegistry? tenantRegistry, out string rejectionReason) =>
        Create(scheme, claims, options, classifier, tenantRegistry, out rejectionReason);

    /// <summary>
    /// ID token do login web: sempre <c>User</c> (um login interativo é de uma pessoa) e, em <c>resource_access</c>, só os papéis
    /// do próprio <see cref="OpenIdConnectWebLoginOptions.ClientId"/>.
    /// </summary>
    public static ExternalIdentity? FromWebLogin(string scheme, IReadOnlyList<Claim> claims, OpenIdConnectWebLoginOptions options,
        ITenantRegistry? tenantRegistry, out string rejectionReason)
    {
        var apiOptions = new OpenIdConnectApiOptions { Authority = options.Authority, Audience = options.ClientId };
        return Create(scheme, claims, apiOptions, classifier: null, tenantRegistry, out rejectionReason);
    }

    /// <summary>Converte os claims; <paramref name="classifier"/> nulo fixa <c>Kind = User</c> (login web).</summary>
    private static ExternalIdentity? Create(string scheme, IReadOnlyList<Claim> claims, OpenIdConnectApiOptions options,
        KindClassifier? classifier, ITenantRegistry? tenantRegistry, out string rejectionReason)
    {
        rejectionReason = string.Empty;
        string? subject = null;
        string? displayName = null;
        string? issuer = null;
        string? externalTenant = null;

        var roles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scopes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var claim in claims)
        {
            if (claim.Type == "iss")
            {
                issuer = claim.Value;
                continue;
            }

            issuer ??= claim.Issuer;

            if (claim.Type is "sub" or ClaimTypes.NameIdentifier)
            {
                subject ??= claim.Value;
                continue;
            }

            if (claim.Type == options.NameClaimType || claim.Type is "preferred_username" or "name" or ClaimTypes.Name)
            {
                displayName ??= claim.Value;
                continue;
            }

            if (options.TenantClaim is not null)
            {
                if (claim.Type == options.TenantClaim)
                {
                    if (externalTenant is not null && !string.Equals(externalTenant, claim.Value, StringComparison.Ordinal))
                    {
                        rejectionReason = $"claim de tenant '{options.TenantClaim}' com valores divergentes";
                        return null;
                    }
                    externalTenant = claim.Value;
                }
            }
            else if (claim.Type is "tid" or "tenant_id" or "tenant")
            {
                if (externalTenant is not null && !string.Equals(externalTenant, claim.Value, StringComparison.Ordinal))
                {
                    rejectionReason = "claims genéricos de tenant com valores divergentes";
                    return null;
                }
                externalTenant = claim.Value;
            }

            if (claim.Type is "scope" or "scp")
            {
                foreach (string part in claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    scopes.Add(part);
                continue;
            }

            if (!string.IsNullOrWhiteSpace(options.RoleClaimType))
            {
                if (claim.Type == options.RoleClaimType)
                {
                    ExtractRoles(claim.Value, roles);
                    continue;
                }
            }
            else if (claim.Type is "roles" or "role" or ClaimTypes.Role)
            {
                ExtractRoles(claim.Value, roles);
                continue;
            }

            // Suporte nativo ao padrão Keycloak realm_access e resource_access
            if (claim.Type == "realm_access")
            {
                ExtractRealmRoles(claim.Value, roles);
            }
            else if (claim.Type == "resource_access")
            {
                ExtractResourceAccessRoles(claim.Value, options.Audience, options.Audiences, roles);
            }
        }

        if (string.IsNullOrWhiteSpace(subject))
        {
            rejectionReason = "claim 'sub' ausente no token";
            return null;
        }

        PrincipalKind kind;
        if (classifier is null)
        {
            kind = PrincipalKind.User;
        }
        else if (classifier.Classify(claims, subject, out rejectionReason) is { } classified)
        {
            kind = classified;
        }
        else
        {
            return null;
        }

        string? resolvedTenant = null;
        string? tenantLookupKey = externalTenant ?? issuer;

        if (options.MultiTenant)
        {
            if (tenantRegistry is null)
            {
                rejectionReason = "validação multi-tenant requer ITenantRegistry registrado";
                return null;
            }

            // O valor vem do token: no motivo (que vai para o log) só o tamanho e um identificador, nunca o texto
            if (!SecurityRules.IsValidUserId(tenantLookupKey))
            {
                rejectionReason = "tenant do token ausente ou fora do formato (" + SensitiveDataMasker.DescribeUntrusted(tenantLookupKey) + ")";
                return null;
            }

            var tenantInfo = tenantRegistry.FindByExternalId(ProviderName, tenantLookupKey!);
            if (tenantInfo is null || !tenantInfo.Enabled)
            {
                rejectionReason = "tenant do token não cadastrado ou inativo (" + SensitiveDataMasker.DescribeUntrusted(tenantLookupKey) + ")";
                return null;
            }

            resolvedTenant = tenantInfo.Id;
            externalTenant ??= tenantLookupKey;
        }
        else if (tenantRegistry is not null && SecurityRules.IsValidUserId(tenantLookupKey))
        {
            var tenantInfo = tenantRegistry.FindByExternalId(ProviderName, tenantLookupKey!);
            if (tenantInfo is { Enabled: true })
            {
                resolvedTenant = tenantInfo.Id;
                externalTenant ??= tenantLookupKey;
            }
        }

        return new ExternalIdentity
        {
            Scheme = scheme,
            Provider = ProviderName,
            UserId = subject!,
            Kind = kind,
            ExternalTenantId = externalTenant,
            TenantId = resolvedTenant,
            MultiTenant = options.MultiTenant,
            Name = displayName ?? subject!,
            Roles = [.. roles],
            Scopes = [.. scopes]
        };
    }

    private static void ExtractRoles(string rawValue, HashSet<string> target)
    {
        if (string.IsNullOrWhiteSpace(rawValue))
            return;

        if (rawValue.TrimStart().StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(rawValue);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in doc.RootElement.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String && item.GetString() is { } r && !string.IsNullOrWhiteSpace(r))
                            target.Add(r);
                    }
                    return;
                }
            }
            catch (JsonException)
            {
                // Fallback para string simples
            }
        }

        target.Add(rawValue);
    }

    private static void ExtractRealmRoles(string json, HashSet<string> target)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("roles", out var rolesElem) &&
                rolesElem.ValueKind == JsonValueKind.Array)
            {
                foreach (var role in rolesElem.EnumerateArray())
                {
                    if (role.ValueKind == JsonValueKind.String && role.GetString() is { } r && !string.IsNullOrWhiteSpace(r))
                        target.Add(r);
                }
            }
        }
        catch (JsonException)
        {
            // Ignora JSON malformado
        }
    }

    /// <summary>
    /// Papéis de <c>resource_access</c> (Keycloak) só dos clients alvo (audiências da API ou client id do login web), com
    /// comparação exata. Sem client alvo, nenhum: importar os papéis de todos os clients daria a esta aplicação papéis de outras
    /// (ex.: <c>realm-management</c>).
    /// </summary>
    private static void ExtractResourceAccessRoles(string json, string? primaryAudience, IReadOnlyCollection<string>? allowedAudiences, HashSet<string> target)
    {
        var targetClients = new HashSet<string>(StringComparer.Ordinal);
        if (!string.IsNullOrWhiteSpace(primaryAudience))
            targetClients.Add(primaryAudience);
        if (allowedAudiences is not null)
        {
            foreach (var aud in allowedAudiences)
            {
                if (!string.IsNullOrWhiteSpace(aud))
                    targetClients.Add(aud);
            }
        }

        if (targetClients.Count == 0)
            return;

        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return;

            foreach (var clientProp in doc.RootElement.EnumerateObject())
            {
                if (!targetClients.Contains(clientProp.Name))
                    continue;

                if (clientProp.Value.ValueKind == JsonValueKind.Object &&
                    clientProp.Value.TryGetProperty("roles", out var rolesElem) &&
                    rolesElem.ValueKind == JsonValueKind.Array)
                {
                    foreach (var role in rolesElem.EnumerateArray())
                    {
                        if (role.ValueKind == JsonValueKind.String && role.GetString() is { } r && !string.IsNullOrWhiteSpace(r))
                            target.Add(r);
                    }
                }
            }
        }
        catch (JsonException)
        {
            // Ignora JSON malformado
        }
    }
}

/// <summary>
/// Regras de <see cref="OpenIdConnectKindOptions"/> já conferidas e compiladas (uma instância por esquema, criada no registro).
/// </summary>
internal sealed class KindClassifier
{
    // Claims que o usuário ou o administrador do tenant editam: não decidem o tipo da identidade
    private static readonly HashSet<string> MutableClaims = new(StringComparer.OrdinalIgnoreCase)
    {
        "preferred_username", "name", "given_name", "family_name", "middle_name", "nickname", "email", "upn", "unique_name"
    };

    private static readonly string[] ClientClaims = ["azp", "client_id", "clientId", "cid", "appid"];

    private readonly ClaimRule[] _application;
    private readonly ClaimRule[] _user;
    private readonly bool _subjectIsClient;
    private readonly bool _entraIdScp;
    private readonly OpenIdConnectUnresolvedKind _unresolved;

    private KindClassifier(ClaimRule[] application, ClaimRule[] user, bool subjectIsClient, bool entraIdScp, OpenIdConnectUnresolvedKind unresolved)
    {
        _application = application;
        _user = user;
        _subjectIsClient = subjectIsClient;
        _entraIdScp = entraIdScp;
        _unresolved = unresolved;
    }

    /// <summary>Confere e compila as regras do esquema.</summary>
    /// <exception cref="InvalidOperationException">Regra fora do formato, sobre claim editável ou reservado, ou valor inválido.</exception>
    public static KindClassifier Create(OpenIdConnectApiOptions options, string scheme)
    {
        ArgumentNullException.ThrowIfNull(options);
        var kind = options.Kind;
        if (!Enum.IsDefined(kind.Unresolved))
            throw new InvalidOperationException($"OpenID Connect '{scheme}': Kind.Unresolved inválido.");

        return new KindClassifier(
            Parse(kind.ApplicationClaims, scheme, nameof(kind.ApplicationClaims)),
            Parse(kind.UserClaims, scheme, nameof(kind.UserClaims)),
            kind.ApplicationWhenSubjectIsClient,
            kind.UseEntraIdScpRule ?? IsEntraIdAuthority(options.Authority),
            kind.Unresolved);
    }

    /// <summary>O tipo da identidade, ou <c>null</c> (recusa) com o motivo, sem valores do token.</summary>
    public PrincipalKind? Classify(IReadOnlyList<Claim> claims, string subject, out string reason)
    {
        bool application = MatchesAny(claims, _application) || (_subjectIsClient && SubjectIsClient(claims, subject));
        bool user = MatchesAny(claims, _user);

        if (_entraIdScp)
        {
            if (HasDelegatedScope(claims))
                user = true;
            else
                application = true;
        }

        reason = string.Empty;
        if (application && user)
        {
            reason = "tipo da identidade ambíguo: o token tem sinais de usuário e de aplicação (ajuste Kind no esquema)";
            return null;
        }

        if (application)
            return PrincipalKind.Application;
        if (user)
            return PrincipalKind.User;

        switch (_unresolved)
        {
            case OpenIdConnectUnresolvedKind.User:
                return PrincipalKind.User;
            case OpenIdConnectUnresolvedKind.Application:
                return PrincipalKind.Application;
            default:
                reason = "tipo da identidade indeterminado: nenhuma regra de usuário ou de aplicação reconheceu o token (ajuste Kind no esquema)";
                return null;
        }
    }

    /// <summary>Authority do Microsoft Entra ID (nuvens pública, governamental dos EUA, China e External ID).</summary>
    internal static bool IsEntraIdAuthority(string? authority) =>
        Uri.TryCreate(authority, UriKind.Absolute, out var uri)
        && (uri.Host.Equals("login.microsoftonline.com", StringComparison.OrdinalIgnoreCase)
            || uri.Host.Equals("login.microsoftonline.us", StringComparison.OrdinalIgnoreCase)
            || uri.Host.Equals("login.partner.microsoftonline.cn", StringComparison.OrdinalIgnoreCase)
            || uri.Host.Equals("login.chinacloudapi.cn", StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith(".ciamlogin.com", StringComparison.OrdinalIgnoreCase));

    private static bool MatchesAny(IReadOnlyList<Claim> claims, ClaimRule[] rules)
    {
        foreach (var rule in rules)
        {
            foreach (var claim in claims)
            {
                if (rule.Matches(claim))
                    return true;
            }
        }

        return false;
    }

    private static bool SubjectIsClient(IReadOnlyList<Claim> claims, string subject)
    {
        foreach (var claim in claims)
        {
            if (Array.IndexOf(ClientClaims, claim.Type) >= 0 && string.Equals(claim.Value, subject, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    // Token de agente autônomo do Entra ID traz scp vazio ou "/" (sem escopo delegado)
    private static bool HasDelegatedScope(IReadOnlyList<Claim> claims)
    {
        foreach (var claim in claims)
        {
            if (claim.Type == "scp" && claim.Value.Trim() is { Length: > 0 } value && value != "/")
                return true;
        }

        return false;
    }

    private static ClaimRule[] Parse(List<string>? rules, string scheme, string property)
    {
        if (rules is null)
            return [];

        var parsed = new List<ClaimRule>(rules.Count);
        foreach (string? rule in rules)
        {
            int separator = rule?.IndexOf('=', StringComparison.Ordinal) ?? -1;
            string claimType = separator > 0 ? rule![..separator] : string.Empty;
            string value = separator > 0 ? rule![(separator + 1)..] : string.Empty;

            if (claimType.Length == 0 || value.Length == 0 || claimType.Any(char.IsWhiteSpace) || value.Any(char.IsControl))
                throw new InvalidOperationException($"OpenID Connect '{scheme}': Kind.{property} tem regra fora do formato 'claim=valor'.");
            if (TecClaimTypes.IsReserved(claimType) || MutableClaims.Contains(claimType))
                throw new InvalidOperationException(
                    $"OpenID Connect '{scheme}': Kind.{property} não aceita o claim '{claimType}' (editável pelo usuário ou reservado do TEC.Security).");

            bool any = value == "*";
            bool prefix = !any && value.EndsWith('*');
            parsed.Add(new ClaimRule(claimType, prefix ? value[..^1] : value, prefix, any));
        }

        return [.. parsed];
    }

    private readonly record struct ClaimRule(string ClaimType, string Value, bool Prefix, bool Any)
    {
        public bool Matches(Claim claim) =>
            string.Equals(claim.Type, ClaimType, StringComparison.Ordinal)
            && (Any || (Prefix
                ? claim.Value.StartsWith(Value, StringComparison.Ordinal)
                : string.Equals(claim.Value, Value, StringComparison.Ordinal)));
    }
}
