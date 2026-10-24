using System.Security.Claims;
using System.Text.Json;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.Claims;

namespace TEC.Security.OpenIdConnect.Internal;

/// <summary>Converte claims OIDC/OAuth 2.0 padrão na identidade externa normalizada pelo TEC.Security.</summary>
internal static class OpenIdConnectIdentity
{
    public const string ProviderName = "OpenIdConnect";

    public static ExternalIdentity? FromClaims(string scheme, IReadOnlyList<Claim> claims, OpenIdConnectApiOptions options,
        ITenantRegistry? tenantRegistry, out string rejectionReason)
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

        string? resolvedTenant = null;
        string? tenantLookupKey = externalTenant ?? issuer;

        if (options.MultiTenant)
        {
            if (tenantRegistry is null)
            {
                rejectionReason = "validação multi-tenant requer ITenantRegistry registrado";
                return null;
            }

            var tenantInfo = tenantRegistry.FindByExternalId(ProviderName, tenantLookupKey ?? string.Empty);
            if (tenantInfo is null || !tenantInfo.Enabled)
            {
                rejectionReason = $"tenant '{tenantLookupKey}' não encontrado ou inativo no cadastro de tenants";
                return null;
            }

            resolvedTenant = tenantInfo.Id;
            externalTenant ??= tenantLookupKey;
        }
        else if (tenantRegistry is not null && tenantLookupKey is not null)
        {
            var tenantInfo = tenantRegistry.FindByExternalId(ProviderName, tenantLookupKey);
            if (tenantInfo is { Enabled: true })
            {
                resolvedTenant = tenantInfo.Id;
                externalTenant ??= tenantLookupKey;
            }
        }

        bool isApplication = false;
        string? gty = claims.FirstOrDefault(c => c.Type == "gty")?.Value;
        string? idtyp = claims.FirstOrDefault(c => c.Type == "idtyp")?.Value;
        string? azp = claims.FirstOrDefault(c => c.Type == "azp")?.Value;
        string? clientIdClaim = claims.FirstOrDefault(c => c.Type is "client_id" or "clientId")?.Value;
        string? prefUser = claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;

        if (string.Equals(gty, "client-credentials", StringComparison.OrdinalIgnoreCase))
        {
            isApplication = true;
        }
        else if (string.Equals(idtyp, "app", StringComparison.OrdinalIgnoreCase))
        {
            isApplication = true;
        }
        else if (prefUser is not null && prefUser.StartsWith("service-account-", StringComparison.OrdinalIgnoreCase))
        {
            isApplication = true;
        }
        else if (subject is not null && (
            (azp is not null && string.Equals(subject, azp, StringComparison.OrdinalIgnoreCase)) ||
            (clientIdClaim is not null && string.Equals(subject, clientIdClaim, StringComparison.OrdinalIgnoreCase))))
        {
            bool hasUserSignal = claims.Any(c => c.Type is "email" or "upn" or "sid" or "auth_time");
            if (!hasUserSignal)
                isApplication = true;
        }

        var kind = isApplication ? PrincipalKind.Application : PrincipalKind.User;

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

    private static void ExtractResourceAccessRoles(string json, string? primaryAudience, IReadOnlyCollection<string>? allowedAudiences, HashSet<string> target)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return;

            var targetClients = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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

            foreach (var clientProp in doc.RootElement.EnumerateObject())
            {
                // Isola os papéis estritamente aos clientes autorizados desta API
                if (targetClients.Count > 0 && !targetClients.Contains(clientProp.Name))
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
