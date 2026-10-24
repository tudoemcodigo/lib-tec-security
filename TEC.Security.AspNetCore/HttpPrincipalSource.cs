using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using TEC.Security.Abstractions;
using TEC.Security.Context;

namespace TEC.Security.AspNetCore;

/// <summary>
/// Principal da operação: o definido por <see cref="ISecurityContext.RunAs"/> (tem precedência) ou o <c>HttpContext.User</c>
/// da requisição atual.
/// </summary>
internal sealed class HttpPrincipalSource(ISecurityContext context, IHttpContextAccessor accessor) : IPrincipalSource
{
    public ClaimsPrincipal? Principal => context.Current ?? accessor.HttpContext?.User;
}
