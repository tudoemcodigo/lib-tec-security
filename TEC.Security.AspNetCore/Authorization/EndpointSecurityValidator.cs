using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using TEC.Security.AspNetCore.Internal;

namespace TEC.Security.AspNetCore.Authorization;

/// <summary>
/// Confere os endpoints na inicialização (<see cref="SecurityAspNetCoreOptions.ValidateEndpointsOnStartup"/>): impede a aplicação
/// de subir com uma regra de autorização que seria ignorada ou degradada em silêncio.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><description><c>[TecAuthorize]</c> com valor vazio ou fora do formato.</description></item>
/// <item><description><c>[TecAuthorize]</c> e <c>[AllowAnonymous]</c> no mesmo endpoint (ex.: <c>[AllowAnonymous]</c> no controller
/// e <c>[TecAuthorize]</c> na action): o ASP.NET Core deixaria o endpoint público.</description></item>
/// </list>
/// Endpoints sem nenhum metadado de autorização não falham: a FallbackPolicy exige identidade autenticada.
/// </remarks>
internal sealed class EndpointSecurityValidator(SecurityAspNetCoreOptions options, ILogger<EndpointSecurityValidator> logger) : IStartupFilter
{
    // IStartupFilter: roda na montagem do pipeline, depois que as rotas do WebApplication foram ligadas ao roteamento
    // (um IHostedService comum roda antes e veria a lista de endpoints vazia). Uma exceção aqui impede o servidor de subir.
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        next(app);

        if (!options.ValidateEndpointsOnStartup || app.ApplicationServices.GetService<EndpointDataSource>() is not { } dataSource)
            return;

        var errors = Validate(dataSource.Endpoints);
        if (errors.Count > 0)
            throw new InvalidOperationException("Configuração de autorização inválida:" + Environment.NewLine + string.Join(Environment.NewLine, errors));

        AspNetCoreSecurityLog.EndpointsValidated(logger, dataSource.Endpoints.Count);
    };

    internal static List<string> Validate(IEnumerable<Endpoint> endpoints)
    {
        var errors = new List<string>();
        foreach (var endpoint in endpoints)
        {
            var attributes = endpoint.Metadata.GetOrderedMetadata<TecAuthorizeAttribute>();
            if (attributes.Count == 0)
                continue;

            string name = endpoint.DisplayName ?? endpoint.ToString() ?? "?";

            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
                errors.Add($"- '{name}': [TecAuthorize] combinado com [AllowAnonymous] (o endpoint ficaria público).");

            foreach (var attribute in attributes)
            {
                try
                {
                    _ = attribute.ToRequirement();
                }
                catch (InvalidOperationException exception)
                {
                    errors.Add($"- '{name}': {exception.Message}");
                }
            }
        }

        return errors;
    }
}
