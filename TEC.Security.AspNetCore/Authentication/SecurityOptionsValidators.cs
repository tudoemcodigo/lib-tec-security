using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace TEC.Security.AspNetCore.Authentication;

/// <summary>
/// Confere os controles obrigatórios dos esquemas do TEC.Security <b>depois</b> de toda configuração (inclusive
/// <c>PostConfigure</c> e <c>Configure</c> registrados pela aplicação depois do <c>AddTecSecurity</c>). Um ajuste tardio que
/// desligue validação ou troque os eventos é recusado, em vez de valer em silêncio.
/// </summary>
internal sealed class SecurityOptionsValidators(SecuritySchemes schemes) :
    IValidateOptions<JwtBearerOptions>, IValidateOptions<CookieAuthenticationOptions>, IValidateOptions<OpenIdConnectOptions>
{
    public ValidateOptionsResult Validate(string? name, JwtBearerOptions options)
    {
        if (name is null || !schemes.Bearer.Any(b => b.Scheme == name))
            return ValidateOptionsResult.Skip;

        return Check(() =>
        {
            JwtHardening.Enforce(options, name);
            Require(options.EventsType is null && options.Events is TecJwtBearerEvents,
                $"Esquema '{name}': Events/EventsType não podem ser substituídos (a normalização da identidade seria pulada).");
        });
    }

    public ValidateOptionsResult Validate(string? name, CookieAuthenticationOptions options)
    {
        if (name is null || name != schemes.CookieScheme)
            return ValidateOptionsResult.Skip;

        return Check(() =>
        {
            SecurityBuilderWebLoginExtensions.EnforceCookie(options, name);
            Require(options.EventsType is null && options.Events is TecCookieEvents,
                $"Esquema '{name}': Events/EventsType do cookie não podem ser substituídos (a revalidação da sessão seria pulada).");
        });
    }

    public ValidateOptionsResult Validate(string? name, OpenIdConnectOptions options)
    {
        if (name is null || schemes.CookieScheme is null || name != schemes.CookieScheme + ".oidc")
            return ValidateOptionsResult.Skip;

        return Check(() =>
        {
            SecurityBuilderWebLoginExtensions.EnforceOidc(options, name);
            Require(options.EventsType is null && options.Events is TecOpenIdConnectEvents,
                $"Esquema '{name}': Events/EventsType não podem ser substituídos (a normalização da identidade seria pulada).");
            Require(!options.GetClaimsFromUserInfoEndpoint,
                $"Esquema '{name}': GetClaimsFromUserInfoEndpoint não é suportado (claims do userinfo entrariam depois da normalização).");
        });
    }

    private static ValidateOptionsResult Check(Action validate)
    {
        try
        {
            validate();
            return ValidateOptionsResult.Success;
        }
        catch (InvalidOperationException exception)
        {
            return ValidateOptionsResult.Fail(exception.Message);
        }
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException(message);
    }
}

/// <summary>
/// Cria as opções de todos os esquemas do TEC.Security na inicialização do host: configuração insegura (ou provedor de teste
/// fora do ambiente permitido) impede a aplicação de subir, em vez de falhar só na primeira requisição.
/// </summary>
internal sealed class SecuritySchemesStartupValidator(
    SecuritySchemes schemes,
    IOptionsMonitor<JwtBearerOptions> bearer,
    IOptionsMonitor<CookieAuthenticationOptions> cookie,
    IOptionsMonitor<OpenIdConnectOptions> oidc) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var registration in schemes.Bearer)
            _ = bearer.Get(registration.Scheme);

        if (schemes.CookieScheme is { } cookieScheme)
        {
            _ = cookie.Get(cookieScheme);
            _ = oidc.Get(cookieScheme + ".oidc");
        }

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
