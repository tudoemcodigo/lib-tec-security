using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using TEC.Security.AspNetCore.Authentication;

namespace TEC.Security.AspNetCore;

/// <summary>Endpoints de entrar e sair do login web.</summary>
public static class WebLoginEndpoints
{
    /// <summary>
    /// Mapeia <c>GET {prefix}/login?returnUrl=/caminho</c> (inicia o login no provedor) e <c>POST {prefix}/logout</c> (encerra a
    /// sessão local e no provedor).
    /// </summary>
    /// <remarks>
    /// <para><c>returnUrl</c> só aceita caminho local (começa com <c>/</c>, sem <c>//</c>, <c>/\</c> nem esquema): um link de
    /// login não pode redirecionar para um site externo depois da autenticação (open redirect). Fora disso, vai para <c>/</c>.</para>
    /// <para>Logout só por POST e só do próprio site (<c>Sec-Fetch-Site</c>/<c>Origin</c>): nem um <c>&lt;img src="/logout"&gt;</c> nem
    /// um formulário de outro site encerram a sessão do usuário (CSRF de logout).</para>
    /// </remarks>
    public static RouteGroupBuilder MapTecWebLogin(this IEndpointRouteBuilder endpoints, string prefix = "/account")
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var group = endpoints.MapGroup(prefix);

        group.MapGet("/login", (RequestDelegate)(context =>
        {
            var schemes = context.RequestServices.GetRequiredService<SecuritySchemes>();
            string cookie = schemes.CookieScheme
                            ?? throw new InvalidOperationException("Nenhum login web registrado (ex.: security.AddEntraIdWebLogin(...)).");

            string? returnUrl = context.Request.Query["returnUrl"].Count == 1 ? context.Request.Query["returnUrl"][0] : null;
            return context.ChallengeAsync(cookie, new AuthenticationProperties { RedirectUri = SafeReturnUrl(returnUrl) });
        })).AllowAnonymous();

        group.MapPost("/logout", (RequestDelegate)(async context =>
        {
            if (!IsSameOrigin(context.Request))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }

            var schemes = context.RequestServices.GetRequiredService<SecuritySchemes>();
            if (schemes.CookieScheme is not { } cookie)
            {
                context.Response.StatusCode = StatusCodes.Status404NotFound;
                return;
            }

            await context.SignOutAsync(cookie).ConfigureAwait(false);
            await context.SignOutAsync(cookie + ".oidc", new AuthenticationProperties { RedirectUri = "/" }).ConfigureAwait(false);
        })).AllowAnonymous();

        return group;
    }

    /// <summary>
    /// Requisição do próprio site: <c>Sec-Fetch-Site</c> (navegadores atuais) igual a <c>same-origin</c> ou, sem ele, <c>Origin</c>
    /// igual ao host. Um formulário de outro site que dispare o logout é recusado (CSRF).
    /// </summary>
    internal static bool IsSameOrigin(HttpRequest request)
    {
        string? fetchSite = request.Headers["Sec-Fetch-Site"];
        if (!string.IsNullOrEmpty(fetchSite))
            return string.Equals(fetchSite, "same-origin", StringComparison.OrdinalIgnoreCase);

        string? origin = request.Headers.Origin;
        if (string.IsNullOrEmpty(origin))
            return false;

        return Uri.TryCreate(origin, UriKind.Absolute, out var uri)
               && string.Equals(uri.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase)
               && string.Equals(uri.Authority, request.Host.Value, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Caminho local seguro para redirecionar, ou <c>/</c>.</summary>
    internal static string SafeReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl) || returnUrl.Length > 2048 || returnUrl[0] != '/')
            return "/";

        if (returnUrl.Length > 1 && (returnUrl[1] == '/' || returnUrl[1] == '\\'))
            return "/";

        return returnUrl.Any(c => char.IsControl(c) || c == '\\') ? "/" : returnUrl;
    }
}
