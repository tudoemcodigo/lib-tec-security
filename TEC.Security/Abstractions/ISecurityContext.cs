using System.Security.Claims;
using TEC.Core.Common.Results;

namespace TEC.Security.Abstractions;

/// <summary>
/// Define a identidade da operação fora de uma requisição HTTP (workers, jobs, consumidores de mensagens) ou para um trecho
/// específico de uma requisição. Singleton; o escopo vale para o fluxo assíncrono atual (<see cref="AsyncLocal{T}"/>).
/// </summary>
/// <remarks>
/// <para>A identidade definida aqui tem precedência sobre o <c>HttpContext.User</c> até o <see cref="IDisposable"/> retornado
/// ser descartado. Escopos podem ser aninhados: ao descartar, volta a identidade anterior.</para>
/// <para>Segurança: <see cref="CreateSystemPrincipalAsync"/> cria uma identidade <see cref="TEC.Core.Security.PrincipalKind.System"/> que só
/// existe dentro do processo; nenhum token externo consegue produzir esse tipo (claims <c>tec_*</c> do token são descartados).</para>
/// </remarks>
/// <example>
/// <code>
/// public sealed class FechamentoJob(ISecurityContext seguranca, IMediator mediator) : BackgroundService
/// {
///     protected override async Task ExecuteAsync(CancellationToken stoppingToken)
///     {
///         var sistema = await seguranca.CreateSystemPrincipalAsync("fechamento-mensal", "cliente-x", cancellationToken: stoppingToken);
///         using (seguranca.RunAs(sistema.Value))
///             await mediator.SendAsync(new FecharMesCommand(), stoppingToken);
///     }
/// }
/// </code>
/// </example>
public interface ISecurityContext
{
    /// <summary>Identidade definida para o fluxo atual, ou <c>null</c>.</summary>
    ClaimsPrincipal? Current { get; }

    /// <summary>
    /// Executa o fluxo atual com <paramref name="principal"/> até o retorno ser descartado. O principal precisa ter sido criado
    /// pelo TEC.Security (normalizado): um principal qualquer é recusado com <see cref="InvalidOperationException"/>.
    /// </summary>
    IDisposable RunAs(ClaimsPrincipal principal);

    /// <summary>
    /// Cria a identidade de sistema <paramref name="serviceName"/> (id <c>system:{serviceName}</c>), opcionalmente vinculada a um
    /// tenant cadastrado e ativo, com os papéis informados (convertidos em permissões como os de qualquer identidade). Falha com
    /// <see cref="Common.SecurityErrors"/> se o nome for inválido ou o tenant não existir/estiver inativo.
    /// </summary>
    Task<Result<ClaimsPrincipal>> CreateSystemPrincipalAsync(string serviceName, string? tenantId = null, IEnumerable<string>? roles = null,
        CancellationToken cancellationToken = default);
}
