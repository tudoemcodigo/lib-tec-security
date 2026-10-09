using Microsoft.Extensions.Logging;

namespace TEC.Security.Internal;

/// <summary>
/// Mensagens de log do núcleo (source generator: sem alocação quando o nível está desabilitado). Eventos 3000-3199.
/// Segurança: tokens, segredos de API key, e-mails e nomes nunca são registrados; apenas esquema, motivo, ids técnicos
/// (id de API key, id de tenant) e contagens.
/// </summary>
internal static partial class SecurityLog
{
    [LoggerMessage(3001, LogLevel.Warning, "Segurança {Scheme}: identidade recusada: {Reason}.")]
    public static partial void IdentityRejected(ILogger logger, string scheme, string reason);

    [LoggerMessage(3002, LogLevel.Warning, "Segurança {Scheme}: {Count} {Kind} fora do formato descartados.")]
    public static partial void InvalidValuesDiscarded(ILogger logger, string scheme, string kind, int count);

    [LoggerMessage(3003, LogLevel.Error, "Segurança {Scheme}: o IPermissionStore lançou {ExceptionType}; autenticação recusada.")]
    public static partial void PermissionStoreFailed(ILogger logger, Exception exception, string scheme, string exceptionType);

    [LoggerMessage(3100, LogLevel.Information, "Segurança: cadastro de tenants recarregado ({Count} tenants).")]
    public static partial void TenantsReloaded(ILogger logger, int count);

    [LoggerMessage(3101, LogLevel.Error, "Segurança: recarga do cadastro de tenants recusada, o cadastro anterior continua valendo: {Reason}")]
    public static partial void TenantReloadRejected(ILogger logger, string reason);

    [LoggerMessage(3110, LogLevel.Warning, "Auditoria de segurança: API key recusada ({Reason}); id '{KeyId}'.")]
    public static partial void ApiKeyRejected(ILogger logger, string reason, string keyId);

    [LoggerMessage(3111, LogLevel.Error, "Segurança: API key '{KeyId}' ignorada por configuração inválida: {Reason}")]
    public static partial void ApiKeyMisconfigured(ILogger logger, string keyId, string reason);

    [LoggerMessage(3120, LogLevel.Error, "Segurança {Provider}: falha ao obter token de serviço: {ErrorType}.")]
    public static partial void TokenAcquisitionFailed(ILogger logger, Exception exception, string provider, string errorType);

    [LoggerMessage(3122, LogLevel.Warning,
        "Segurança {Provider}: renovação do token de serviço falhou ({ErrorType}); o token atual, ainda válido, continua em uso.")]
    public static partial void TokenRefreshFailedUsingCurrent(ILogger logger, Exception exception, string provider, string errorType);

    [LoggerMessage(3121, LogLevel.Warning,
        "Segurança: requisição bloqueada, o destino não pode receber o token de serviço (fora de AllowedHosts ou sem HTTPS; host '{Host}').")]
    public static partial void TokenNotAttached(ILogger logger, string host);

    [LoggerMessage(3123, LogLevel.Warning,
        "Segurança {Provider}: circuito aberto após falhas repetidas do provedor de identidade; chamadas recusadas por {BreakSeconds} s.")]
    public static partial void CircuitOpened(ILogger logger, string provider, double breakSeconds);

    [LoggerMessage(3124, LogLevel.Information, "Segurança {Provider}: circuito meio-aberto; testando o provedor de identidade com uma chamada.")]
    public static partial void CircuitHalfOpened(ILogger logger, string provider);

    [LoggerMessage(3125, LogLevel.Information, "Segurança {Provider}: circuito fechado; o provedor de identidade voltou a responder.")]
    public static partial void CircuitClosed(ILogger logger, string provider);
}
