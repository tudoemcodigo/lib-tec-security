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

            if (options.TenantClaim is not null && claim.Type == options.TenantClaim)
            {
                externalTenant ??= claim.Value;
                continue;
            }

            if (claim.Type is "tid" or "tenant_id" or "tenant")
            {
                externalTenant ??= claim.Value;
                continue;
            }

            if (claim.Type is "scope" or "scp")
            {
                foreach (string part in claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    scopes.Add(part);
                continue;
            }

            if (claim.Type == options.RoleClaimType || claim.Type is "roles" or "role" or ClaimTypes.Role)
            {
                ExtractRoles(claim.Value, roles);
                continue;
            }

            // Suporte nativo ao padrão Keycloak realm_access e resource_access
            if (claim.Type is "realm_access" or "resource_access")
            {
                ExtractJsonRoles(claim.Value, roles);
            }
        }

        if (string.IsNullOrWhiteSpace(subject))
        {
            rejectionReason = "claim 'sub' ausente no token";
            return null;
        }

        string? resolvedTenant = null;
        if (options.MultiTenant)
        {
            if (tenantRegistry is null)
            {
                rejectionReason = "validação multi-tenant requer ITenantRegistry registrado";
                return null;
            }

            string tenantLookupKey = externalTenant ?? issuer ?? string.Empty;
            var tenantInfo = tenantRegistry.FindByExternalId(ProviderName, tenantLookupKey);
            if (tenantInfo is null || !tenantInfo.Enabled)
            {
                rejectionReason = $"tenant '{tenantLookupKey}' não encontrado ou inativo no cadastro de tenants";
                return null;
            }

            resolvedTenant = tenantInfo.Id;
        }
        else if (externalTenant is not null && tenantRegistry is not null)
        {
            var tenantInfo = tenantRegistry.FindByExternalId(ProviderName, externalTenant);
            if (tenantInfo is { Enabled: true })
                resolvedTenant = tenantInfo.Id;
        }

        var kind = (roles.Count == 0 && scopes.Count > 0 && !claims.Any(c => c.Type is "email" or "preferred_username"))
            ? PrincipalKind.Application
            : PrincipalKind.User;

        return new ExternalIdentity
        {
            Scheme = scheme,
            Provider = ProviderName,
            UserId = subject,
            Kind = kind,
            ExternalTenantId = externalTenant,
            TenantId = resolvedTenant,
            Name = displayName ?? subject,
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

    private static void ExtractJsonRoles(string json, HashSet<string> target)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            FindRolesInElement(doc.RootElement, target);
        }
        catch (JsonException)
        {
            // Ignora JSON malformado
        }
    }

    private static void FindRolesInElement(JsonElement element, HashSet<string> target)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("roles", out var rolesElement) && rolesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var role in rolesElement.EnumerateArray())
                {
                    if (role.ValueKind == JsonValueKind.String && role.GetString() is { } r && !string.IsNullOrWhiteSpace(r))
                        target.Add(r);
                }
            }

            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                    FindRolesInElement(property.Value, target);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind is JsonValueKind.Object or JsonValueKind.Array)
                    FindRolesInElement(item, target);
            }
        }
    }
}
