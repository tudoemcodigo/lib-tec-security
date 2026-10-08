using TEC.Core.Common.Results;
using TEC.Core.Responses;

namespace TEC.Security.Common;

/// <summary>
/// Erros padronizados do componente de segurança.
/// </summary>
/// <remarks>
/// Segurança: as mensagens são genéricas e nunca dizem <b>por que</b> a autenticação falhou (token expirado, assinatura,
/// emissor, tenant...). O motivo detalhado vai apenas para o log e as métricas, para não orientar um atacante.
/// </remarks>
public static class SecurityErrors
{
    /// <summary>Código: identidade ausente ou inválida.</summary>
    public const string UnauthenticatedCode = "SEGURANCA_NAO_AUTENTICADO";

    /// <summary>Código: identidade sem permissão para a operação.</summary>
    public const string ForbiddenCode = "SEGURANCA_ACESSO_NEGADO";

    /// <summary>Código: tenant não cadastrado ou inativo.</summary>
    public const string TenantNotAllowedCode = "SEGURANCA_TENANT_NAO_PERMITIDO";

    /// <summary>Código: dado de entrada inválido (nome de serviço, papel, permissão...).</summary>
    public const string InvalidInputCode = "SEGURANCA_ENTRADA_INVALIDA";

    /// <summary>Código: falha ao obter token ou credencial no provedor de identidade.</summary>
    public const string ProviderFailureCode = "SEGURANCA_PROVEDOR_INDISPONIVEL";

    /// <summary>Não autenticado (HTTP 401).</summary>
    public static Error Unauthenticated() => Error.Unauthorized(UnauthenticatedCode, ApiResponse.DefaultMessages.Unauthorized);

    /// <summary>Sem permissão (HTTP 403).</summary>
    public static Error Forbidden() => Error.Forbidden(ForbiddenCode, ApiResponse.DefaultMessages.Forbidden);

    /// <summary>
    /// Tenant não permitido (HTTP 401): para o cliente é indistinguível de credencial inválida, para não revelar quais tenants
    /// existem.
    /// </summary>
    public static Error TenantNotAllowed() => Error.Unauthorized(TenantNotAllowedCode, ApiResponse.DefaultMessages.Unauthorized);

    /// <summary>Entrada inválida (HTTP 400). A mensagem nunca repete o valor recebido.</summary>
    public static Error InvalidInput(string field, string message) => Error.Validation(InvalidInputCode, message, field);

    /// <summary>Provedor de identidade indisponível (oculto do cliente, HTTP 502).</summary>
    public static Error ProviderFailure() =>
        Error.ExternalService(ProviderFailureCode, ApiResponse.DefaultMessages.ExternalService);
}
