using Microsoft.AspNetCore.Builder;

namespace TEC.Security.AspNetCore.Authorization;

/// <summary>Autorização do TEC.Security para Minimal APIs, grupos de rotas, gRPC e hubs.</summary>
public static class EndpointConventionBuilderExtensions
{
    /// <summary>
    /// Mesmo efeito de <see cref="TecAuthorizeAttribute"/>: valores separados por vírgula são alternativas; propriedades
    /// diferentes precisam ser todas atendidas; chamadas repetidas se somam.
    /// </summary>
    /// <example>
    /// <code>
    /// var pedidos = app.MapGroup("/pedidos").RequireTecAuthorization(permissions: "pedidos:ler");
    /// pedidos.MapPost("/", Criar).RequireTecAuthorization(permissions: "pedidos:criar");
    /// app.MapHub&lt;ChatHub&gt;("/hubs/chat").RequireTecAuthorization(kinds: TecPrincipalKinds.User);
    /// </code>
    /// </example>
    public static TBuilder RequireTecAuthorization<TBuilder>(this TBuilder builder, string? permissions = null, string? roles = null,
        string? scopes = null, string? schemes = null, TecPrincipalKinds kinds = TecPrincipalKinds.UserOrApplication)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);

        var attribute = new TecAuthorizeAttribute
        {
            Permissions = permissions,
            Roles = roles,
            Scopes = scopes,
            Schemes = schemes,
            Kinds = kinds
        };
        _ = attribute.ToRequirement();   // valida já no mapeamento

        builder.Add(endpoint => endpoint.Metadata.Add(attribute));
        return builder;
    }

    /// <summary>Atalho para <see cref="RequireTecAuthorization{TBuilder}"/> com permissões (basta uma).</summary>
    public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, params string[] permissions)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(permissions);
        if (permissions.Length == 0)
            throw new ArgumentException("Informe ao menos uma permissão.", nameof(permissions));

        return builder.RequireTecAuthorization(permissions: string.Join(',', permissions));
    }
}
