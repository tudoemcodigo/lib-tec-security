using Microsoft.Extensions.Logging;

namespace TEC.Security.EntraId.Internal;

/// <summary>Mensagens de log do provedor Entra ID (eventos 3400-3499). Nunca registra tokens, assertions ou segredos.</summary>
internal static partial class EntraIdLog
{
    [LoggerMessage(3401, LogLevel.Error, "Entra ID: On-Behalf-Of falhou para '{UserId}': {ErrorType}.")]
    public static partial void OnBehalfOfFailed(ILogger logger, Exception exception, string userId, string errorType);

    [LoggerMessage(3402, LogLevel.Error, "Entra ID {Scheme}: falha ao autenticar a aplicação na troca do código de login: {ErrorType}.")]
    public static partial void CodeRedemptionCredentialFailed(ILogger logger, Exception exception, string scheme, string errorType);

    [LoggerMessage(3403, LogLevel.Warning,
        "Entra ID {Scheme}: API multi-tenant com RolesAsPermissions = true. Administradores de tenants clientes podem atribuir qualquer app role aos próprios usuários; prefira RolesAsPermissions = false e permissões por tenant (Security:Permissions:Tenants).")]
    public static partial void MultiTenantRolesAsPermissions(ILogger logger, string scheme);
}
