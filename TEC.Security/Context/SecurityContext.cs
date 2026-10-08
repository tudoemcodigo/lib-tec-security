using System.Security.Claims;
using TEC.Core.Common.Results;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.Claims;
using TEC.Security.Common;

namespace TEC.Security.Context;

/// <summary>
/// Fonte do principal da operação atual. O núcleo usa só o <see cref="ISecurityContext"/>; o <c>TEC.Security.AspNetCore</c>
/// registra uma fonte que também lê o <c>HttpContext.User</c>.
/// </summary>
public interface IPrincipalSource
{
    /// <summary>Principal atual, ou <c>null</c>.</summary>
    ClaimsPrincipal? Principal { get; }
}

/// <summary><see cref="ISecurityContext"/> com <see cref="AsyncLocal{T}"/>: vale para o fluxo assíncrono que chamou <see cref="RunAs"/>.</summary>
internal sealed class SecurityContext(SecurityIdentityFactory factory) : ISecurityContext, IPrincipalSource
{
    /// <summary>Provedor das identidades de sistema.</summary>
    public const string SystemProvider = "System";

    // Por instância (não estática): dois containers no mesmo processo (ex.: testes, hosts lado a lado) não enxergam a
    // identidade um do outro
    private readonly AsyncLocal<Holder?> _current = new();

    public ClaimsPrincipal? Current => _current.Value?.Principal;

    ClaimsPrincipal? IPrincipalSource.Principal => Current;

    public IDisposable RunAs(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        if (SecurityUser.FindNormalizedIdentity(principal) is null)
            throw new InvalidOperationException(
                "RunAs aceita apenas identidades criadas pelo TEC.Security (ex.: CreateSystemPrincipalAsync ou o HttpContext.User autenticado).");

        var previous = _current.Value;
        var holder = new Holder(principal);
        _current.Value = holder;
        return new Scope(_current, holder, previous);
    }

    public Task<Result<ClaimsPrincipal>> CreateSystemPrincipalAsync(string serviceName, string? tenantId = null, IEnumerable<string>? roles = null,
        CancellationToken cancellationToken = default)
    {
        if (!SecurityRules.IsValidServiceName(serviceName))
        {
            return Task.FromResult(Result.Failure<ClaimsPrincipal>(SecurityErrors.InvalidInput(nameof(serviceName),
                "Nome de serviço inválido: use minúsculas, dígitos e hífen (3 a 40 caracteres).")));
        }

        if (tenantId is not null && !SecurityRules.IsValidTenantId(tenantId))
            return Task.FromResult(Result.Failure<ClaimsPrincipal>(SecurityErrors.InvalidInput(nameof(tenantId), "Id de tenant inválido.")));

        return factory.CreateSystemAsync(new ExternalIdentity
        {
            Scheme = SystemProvider,
            Provider = SystemProvider,
            UserId = "system:" + serviceName,
            Kind = PrincipalKind.System,
            TenantId = tenantId,
            Name = serviceName,
            Roles = roles?.ToArray() ?? []
        }, cancellationToken);
    }

    private sealed class Holder(ClaimsPrincipal principal)
    {
        public ClaimsPrincipal? Principal { get; set; } = principal;
    }

    /// <summary>
    /// Restaura a identidade anterior. Também limpa o <see cref="Holder"/>: fluxos filhos que capturaram o contexto (tarefas
    /// iniciadas dentro do escopo e que continuam depois dele) deixam de ver a identidade.
    /// </summary>
    private sealed class Scope(AsyncLocal<Holder?> current, Holder holder, Holder? previous) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            holder.Principal = null;
            if (ReferenceEquals(current.Value, holder))
                current.Value = previous;
        }
    }
}
