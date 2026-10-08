using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using TEC.Core.Common.Results;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Diagnostics;
using TEC.Security.Internal;

namespace TEC.Security.Claims;

/// <summary>
/// Converte a identidade validada por um provedor (<see cref="ExternalIdentity"/>) no principal normalizado do TEC.Security:
/// tenant resolvido pelo cadastro, papéis/escopos/permissões validados e claims <c>tec_*</c> do provedor descartados.
/// Singleton, usado pelos pacotes de provedor (Entra ID, API key...).
/// </summary>
/// <remarks>
/// <para>Falha fechada, sem exceção: identidade incompleta, tenant desconhecido/inativo (com <see cref="SecurityOptions.RequireTenant"/>
/// ou tenant explícito), excesso de papéis/permissões (token inflado) ou falha do <see cref="IPermissionStore"/> resultam em
/// erro, registrado no log com o motivo (evento 3001) e na métrica <c>security.authentication.failures</c>.</para>
/// <para>Valores fora do formato (<see cref="SecurityRules.IsValidName"/>) são descartados individualmente, com log de aviso
/// (só a quantidade, nunca o valor).</para>
/// </remarks>
public sealed class SecurityIdentityFactory
{
    private readonly ITenantRegistry _tenants;
    private readonly IPermissionStore _permissions;
    private readonly IOptionsMonitor<SecurityOptions> _options;
    private readonly ILogger _logger;

    /// <summary>Cria a fábrica.</summary>
    public SecurityIdentityFactory(ITenantRegistry tenants, IPermissionStore permissions, IOptionsMonitor<SecurityOptions> options,
        ILogger<SecurityIdentityFactory>? logger = null)
    {
        ArgumentNullException.ThrowIfNull(tenants);
        ArgumentNullException.ThrowIfNull(permissions);
        ArgumentNullException.ThrowIfNull(options);

        _tenants = tenants;
        _permissions = permissions;
        _options = options;
        _logger = (ILogger?)logger ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }

    /// <summary>
    /// Cria o principal normalizado de uma identidade de usuário ou aplicação. Identidades <see cref="PrincipalKind.System"/>
    /// só podem ser criadas por <see cref="ISecurityContext.CreateSystemPrincipalAsync"/>.
    /// </summary>
    public Task<Result<ClaimsPrincipal>> CreateAsync(ExternalIdentity identity, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (identity.Kind is not (PrincipalKind.User or PrincipalKind.Application))
            return Task.FromResult(Fail(identity, "tipo de identidade não permitido para provedores", SecurityErrors.Unauthenticated()));

        return CreateCoreAsync(identity, cancellationToken);
    }

    /// <summary>
    /// Refaz a normalização de um principal já normalizado (ex.: sessão de login web): o tenant é resolvido de novo pelo id
    /// externo e as permissões são consultadas de novo. Usado para que uma sessão longa reflita tenant desativado e permissões
    /// revogadas.
    /// </summary>
    /// <remarks>Somente identidades de usuário e aplicação; permissões concedidas diretamente (API key) não são preservadas.</remarks>
    public Task<Result<ClaimsPrincipal>> RevalidateAsync(ClaimsPrincipal principal, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var identity = SecurityUser.FindNormalizedIdentity(principal);
        var user = new SecurityUser(principal);
        if (identity is null || !user.IsAuthenticated || user.Scheme is null || user.Provider is null)
            return Task.FromResult(Result.Failure<ClaimsPrincipal>(SecurityErrors.Unauthenticated()));

        return CreateAsync(new ExternalIdentity
        {
            Scheme = user.Scheme,
            Provider = user.Provider,
            UserId = user.Id!,
            Kind = user.Kind,
            ExternalTenantId = user.ExternalTenantId,
            Name = user.Name,
            ClientId = user.ClientId,
            Roles = [.. user.Roles],
            Scopes = [.. user.Scopes],
            SourceClaims = [.. identity.Claims.Where(c => !TecClaimTypes.IsReserved(c.Type))]
        }, cancellationToken);
    }

    internal Task<Result<ClaimsPrincipal>> CreateSystemAsync(ExternalIdentity identity, CancellationToken cancellationToken) =>
        CreateCoreAsync(identity, cancellationToken);

    private async Task<Result<ClaimsPrincipal>> CreateCoreAsync(ExternalIdentity identity, CancellationToken cancellationToken)
    {
        if (!SecurityRules.IsValidName(identity.Scheme) || !SecurityRules.IsValidName(identity.Provider))
            return Fail(identity, "esquema ou provedor fora do formato", SecurityErrors.Unauthenticated());

        if (!SecurityRules.IsValidUserId(identity.UserId))
            return Fail(identity, "identificador da identidade ausente ou fora do formato", SecurityErrors.Unauthenticated());

        var options = _options.CurrentValue;

        // ---------- Tenant: sempre do cadastro, nunca copiado do token ----------
        TenantInfo? tenant;
        if (identity.TenantId is not null)
        {
            tenant = SecurityRules.IsValidTenantId(identity.TenantId) ? _tenants.Find(identity.TenantId) : null;
            if (tenant is null)
                return Fail(identity, "tenant configurado não existe no cadastro", SecurityErrors.TenantNotAllowed());
        }
        else if (!string.IsNullOrEmpty(identity.ExternalTenantId))
        {
            tenant = _tenants.FindByExternalId(identity.Provider, identity.ExternalTenantId);
        }
        else
        {
            tenant = null;
        }

        if (tenant is { Enabled: false })
            return Fail(identity, "tenant inativo", SecurityErrors.TenantNotAllowed());

        if (tenant is null && options.RequireTenant && identity.Kind != PrincipalKind.System)
            return Fail(identity, "identidade sem tenant cadastrado (RequireTenant)", SecurityErrors.TenantNotAllowed());

        // ---------- Papéis, escopos e permissões ----------
        if (!TryNormalize(identity, identity.Roles, "papéis", out var roles))
            return Fail(identity, "quantidade de papéis acima do limite", SecurityErrors.Unauthenticated());

        HashSet<string> scopes = [];
        if (identity.Kind == PrincipalKind.User && !TryNormalize(identity, identity.Scopes, "escopos", out scopes))
            return Fail(identity, "quantidade de escopos acima do limite", SecurityErrors.Unauthenticated());

        IReadOnlyCollection<string> stored;
        try
        {
            stored = await _permissions.GetPermissionsAsync(
                new PermissionContext(identity.Provider, identity.Scheme, identity.UserId, tenant?.Id, identity.Kind, roles),
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            SecurityLog.PermissionStoreFailed(_logger, exception, identity.Scheme, exception.GetType().Name);
            SecurityDiagnostics.RecordAuthenticationFailure(identity.Scheme, "permission_store");
            return SecurityErrors.ProviderFailure();
        }

        IEnumerable<string> candidates = identity.Permissions.Concat(stored ?? []);
        if (options.RolesAsPermissions)
            candidates = candidates.Concat(roles);

        if (!TryNormalize(identity, candidates, "permissões", out var permissions))
            return Fail(identity, "quantidade de permissões acima do limite", SecurityErrors.Unauthenticated());

        // ---------- Identidade normalizada ----------
        var claims = new ClaimsIdentity(identity.Scheme, TecClaimTypes.Name, TecClaimTypes.Role);

        foreach (var claim in identity.SourceClaims)
        {
            if (claim is not null && !TecClaimTypes.IsReserved(claim.Type))
                claims.AddClaim(new Claim(claim.Type, claim.Value, claim.ValueType, claim.Issuer, claim.OriginalIssuer));
        }

        claims.AddClaim(new Claim(TecClaimTypes.Normalized, TecClaimTypes.NormalizedValue));
        claims.AddClaim(new Claim(TecClaimTypes.UserId, identity.UserId));
        claims.AddClaim(new Claim(TecClaimTypes.Kind, identity.Kind.ToString()));
        claims.AddClaim(new Claim(TecClaimTypes.Scheme, identity.Scheme));
        claims.AddClaim(new Claim(TecClaimTypes.Provider, identity.Provider));

        if (tenant is not null)
            claims.AddClaim(new Claim(TecClaimTypes.TenantId, tenant.Id));
        if (SecurityRules.IsValidUserId(identity.ExternalTenantId))
            claims.AddClaim(new Claim(TecClaimTypes.ExternalTenantId, identity.ExternalTenantId!));
        if (SecurityRules.IsValidUserId(identity.ClientId))
            claims.AddClaim(new Claim(TecClaimTypes.ClientId, identity.ClientId!));
        if (SecurityRules.SanitizeDisplayName(identity.Name) is { } name)
            claims.AddClaim(new Claim(TecClaimTypes.Name, name));

        foreach (string role in roles)
            claims.AddClaim(new Claim(TecClaimTypes.Role, role));
        foreach (string scope in scopes)
            claims.AddClaim(new Claim(TecClaimTypes.Scope, scope));
        foreach (string permission in permissions)
            claims.AddClaim(new Claim(TecClaimTypes.Permission, permission));

        return new ClaimsPrincipal(claims);
    }

    /// <summary>Distintos e no formato; fora do formato são descartados (log com a quantidade). <c>false</c> acima do limite.</summary>
    private bool TryNormalize(ExternalIdentity identity, IEnumerable<string> values, string kind, out HashSet<string> result)
    {
        result = new HashSet<string>(StringComparer.Ordinal);
        int discarded = 0;

        foreach (string value in values)
        {
            if (!SecurityRules.IsValidName(value))
            {
                discarded++;
                continue;
            }

            if (result.Add(value) && result.Count > SecurityRules.MaxItemsPerIdentity)
                return false;
        }

        if (discarded > 0)
            SecurityLog.InvalidValuesDiscarded(_logger, identity.Scheme, kind, discarded);

        return true;
    }

    private Result<ClaimsPrincipal> Fail(ExternalIdentity identity, string reason, Error error)
    {
        string scheme = SecurityRules.IsValidName(identity.Scheme) ? identity.Scheme : "invalido";
        SecurityLog.IdentityRejected(_logger, scheme, reason);
        SecurityDiagnostics.RecordAuthenticationFailure(scheme, error.Code == SecurityErrors.TenantNotAllowedCode ? "tenant" : "identity");
        return error;
    }
}
