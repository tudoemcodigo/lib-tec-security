using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using TEC.Core.Security;
using TEC.Core.Text.Masking;
using TEC.Security.AspNetCore.Internal;
using TEC.Security.Claims;
using TEC.Security.Diagnostics;

namespace TEC.Security.AspNetCore.Authorization;

/// <summary>
/// Avalia <see cref="TecRequirement"/> e <see cref="TecAuthenticatedRequirement"/> lendo apenas os claims normalizados.
/// Negações viram <c>context.Fail</c> (nenhum outro handler consegue reverter) com log de auditoria e métrica.
/// </summary>
internal sealed class TecAuthorizationHandler(ILogger<TecAuthorizationHandler> logger) : IAuthorizationHandler
{
    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        var user = new SecurityUser(context.User);

        foreach (var requirement in context.PendingRequirements.ToArray())
        {
            switch (requirement)
            {
                case TecAuthenticatedRequirement:
                    if (user.IsAuthenticated)
                        context.Succeed(requirement);
                    else if (context.User.Identities.Any(i => i.IsAuthenticated))
                    {
                        AspNetCoreSecurityLog.NotNormalized(logger, Endpoint(context), context.User.Identity?.AuthenticationType ?? "?");
                        SecurityDiagnostics.RecordAuthorizationDenied(null, "not_normalized");
                        context.Fail(new AuthorizationFailureReason(this, "identidade sem normalização do TEC.Security"));
                    }

                    // Sem identidade: requisito pendente -> ASP.NET responde 401 (challenge)
                    break;

                case TecRequirement tec:
                    if (!user.IsAuthenticated)
                        break;   // 401

                    string? reason = Evaluate(user, tec);
                    if (reason is null)
                        context.Succeed(requirement);
                    else
                        Deny(context, user, reason);
                    break;
            }
        }

        return Task.CompletedTask;
    }

    /// <summary>Motivo da negação (rótulo de baixa cardinalidade), ou <c>null</c> se atendido.</summary>
    internal static string? Evaluate(SecurityUser user, TecRequirement requirement)
    {
        var kind = user.Kind switch
        {
            PrincipalKind.User => TecPrincipalKinds.User,
            PrincipalKind.Application => TecPrincipalKinds.Application,
            PrincipalKind.System => TecPrincipalKinds.System,
            _ => (TecPrincipalKinds)0
        };

        if ((requirement.Kinds & kind) == 0)
            return "kind";

        if (requirement.Schemes.Count > 0 && (user.Scheme is null || !requirement.Schemes.Contains(user.Scheme, StringComparer.OrdinalIgnoreCase)))
            return "scheme";

        if (requirement.Roles.Count > 0 && !requirement.Roles.Any(user.IsInRole))
            return "role";

        if (requirement.Scopes.Count > 0 && (user.Kind != PrincipalKind.User || !requirement.Scopes.Any(user.HasScope)))
            return "scope";

        if (requirement.Permissions.Count > 0 && !requirement.Permissions.Any(user.HasPermission))
            return "permission";

        return null;
    }

    private void Deny(AuthorizationHandlerContext context, SecurityUser user, string reason)
    {
        AspNetCoreSecurityLog.AccessDenied(logger, Endpoint(context), user.Kind.ToString(), user.Id ?? "?", user.Scheme ?? "?",
            user.TenantId ?? "-", reason);
        SecurityDiagnostics.RecordAuthorizationDenied(user.Scheme, reason);
        context.Fail(new AuthorizationFailureReason(this, reason));
    }

    private static string Endpoint(AuthorizationHandlerContext context) => context.Resource switch
    {
        // Sem endpoint, o caminho da requisição (texto do cliente) não vai para o log: só o tamanho e um identificador
        HttpContext http => http.GetEndpoint()?.DisplayName ?? "caminho " + SensitiveDataMasker.DescribeUntrusted(http.Request.Path.Value),
        Endpoint endpoint => endpoint.DisplayName ?? "?",
        _ => context.Resource?.GetType().Name ?? "?"
    };
}
