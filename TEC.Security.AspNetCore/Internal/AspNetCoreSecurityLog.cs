using Microsoft.Extensions.Logging;

namespace TEC.Security.AspNetCore.Internal;

/// <summary>
/// Mensagens de log da integração ASP.NET Core (eventos 3200-3399). Segurança: tokens, API keys e mensagens de exceção de
/// validação de token (que podem conter partes do token) nunca são registrados; apenas esquema, tipo da exceção, endpoint,
/// motivo e o id estável da identidade (auditoria).
/// </summary>
internal static partial class AspNetCoreSecurityLog
{
    [LoggerMessage(3201, LogLevel.Information, "Segurança {Scheme}: token recusado ({FailureType}).")]
    public static partial void TokenRejected(ILogger logger, string scheme, string failureType);

    [LoggerMessage(3202, LogLevel.Information, "Segurança: credencial recusada: {Reason}.")]
    public static partial void CredentialRejected(ILogger logger, string reason);

    [LoggerMessage(3203, LogLevel.Information,
        "Auditoria de segurança: acesso negado a '{Endpoint}' para {Kind} '{UserId}' (esquema {Scheme}, tenant '{TenantId}'): {Reason}.")]
    public static partial void AccessDenied(ILogger logger, string endpoint, string kind, string userId, string scheme, string tenantId, string reason);

    [LoggerMessage(3204, LogLevel.Warning, "Segurança: acesso negado a '{Endpoint}': identidade autenticada sem normalização do TEC.Security (esquema {Scheme}).")]
    public static partial void NotNormalized(ILogger logger, string endpoint, string scheme);

    [LoggerMessage(3205, LogLevel.Information, "Segurança {Scheme}: sessão encerrada na revalidação: {Reason}.")]
    public static partial void SessionRejected(ILogger logger, string scheme, string reason);

    [LoggerMessage(3206, LogLevel.Information, "Segurança: {Count} endpoints conferidos na inicialização.")]
    public static partial void EndpointsValidated(ILogger logger, int count);

    [LoggerMessage(3207, LogLevel.Information, "Segurança {Scheme}: login web recusado ({FailureType}).")]
    public static partial void RemoteLoginRejected(ILogger logger, string scheme, string failureType);
}
