using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using TEC.Core.Common.Serialization;
using TEC.Core.Responses;
using TEC.Security.Common;

namespace TEC.Security.AspNetCore.Authorization;

/// <summary>Metadados JSON gerados em compilação do envelope de erro (compatível com Native AOT).</summary>
[JsonSerializable(typeof(ApiResponse))]
internal sealed partial class SecurityJsonContext : JsonSerializerContext;

/// <summary>
/// Depois do tratamento padrão (challenge/forbid do esquema), completa as respostas 401/403 sem corpo com o
/// <see cref="ApiResponse"/> do TEC.Core (mesmo formato do TEC.Cqrs.AspNetCore), com código de <see cref="SecurityErrors"/> e
/// <c>traceId</c>. Redirecionamentos (login web) e respostas já escritas não são alterados.
/// </summary>
/// <remarks>A mensagem é sempre genérica: o motivo da negação fica só no log e nas métricas.</remarks>
internal sealed class TecAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private static readonly JsonSerializerOptions JsonOptions = CreateOptions();

    private readonly AuthorizationMiddlewareResultHandler _default = new();

    public async Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        await _default.HandleAsync(next, context, policy, authorizeResult).ConfigureAwait(false);

        if (!authorizeResult.Challenged && !authorizeResult.Forbidden)
            return;

        await WriteBodyAsync(context).ConfigureAwait(false);
    }

    /// <summary>Escreve o corpo de 401/403 se a resposta ainda não tiver corpo.</summary>
    internal static Task WriteBodyAsync(HttpContext context)
    {
        var response = context.Response;
        if (response.HasStarted || response.ContentLength is not null || response.ContentType is not null)
            return Task.CompletedTask;

        var error = response.StatusCode switch
        {
            StatusCodes.Status401Unauthorized => SecurityErrors.Unauthenticated(),
            StatusCodes.Status403Forbidden => SecurityErrors.Forbidden(),
            _ => null
        };
        if (error is null)
            return Task.CompletedTask;

        var body = ApiResponse.Fail(response.StatusCode, error.Message, ApiError.FromError(error)) with
        {
            TraceId = Activity.Current?.TraceId.ToString() ?? context.TraceIdentifier
        };

        response.Headers.CacheControl = "no-store";
        var typeInfo = (JsonTypeInfo<ApiResponse>)JsonOptions.GetTypeInfo(typeof(ApiResponse));
        return response.WriteAsJsonAsync(body, typeInfo, "application/json; charset=utf-8", context.RequestAborted);
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = JsonDefaults.CreateOptions(SecurityJsonContext.Default);
        options.MakeReadOnly();
        return options;
    }
}
