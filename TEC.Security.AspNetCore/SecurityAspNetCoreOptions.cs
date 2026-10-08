using Microsoft.AspNetCore.Http;

namespace TEC.Security.AspNetCore;

/// <summary>Opções da integração com ASP.NET Core (<c>security.AddAspNetCore(o =&gt; ...)</c>).</summary>
public sealed class SecurityAspNetCoreOptions
{
    /// <summary>Nome do esquema padrão (policy scheme) que escolhe o provedor de cada requisição.</summary>
    public const string DefaultScheme = "TEC";

    /// <summary>Esquema usado quando a requisição não traz credencial reconhecida.</summary>
    public const string NoCredentialsScheme = "TEC.None";

    /// <summary>
    /// Caminhos de hubs SignalR que aceitam o token na query string (<c>access_token</c>), porque WebSocket e Server-Sent
    /// Events não enviam o header <c>Authorization</c> pelo navegador. Fora destes caminhos, token na query string é ignorado.
    /// </summary>
    /// <remarks>
    /// A query string costuma aparecer em logs de acesso de proxies e servidores: com hubs, mascare <c>access_token</c> nos logs
    /// (o TEC.Observability já redige os valores da query string nos traces).
    /// </remarks>
    public List<PathString> HubPaths { get; } = [];

    /// <summary>
    /// Tamanho máximo do token aceito, em caracteres. Padrão: 16384. Tokens maiores são recusados antes de qualquer
    /// processamento (proteção contra DoS e tokens inflados).
    /// </summary>
    public int MaxTokenLength { get; set; } = 16 * 1024;

    /// <summary>
    /// Confere os endpoints na inicialização: <c>[TecAuthorize]</c> com valores inválidos ou combinado com <c>[AllowAnonymous]</c>
    /// (que anularia a regra em silêncio) impedem a aplicação de subir. Padrão: <c>true</c>.
    /// </summary>
    public bool ValidateEndpointsOnStartup { get; set; } = true;

    /// <summary>
    /// Exige HTTPS para requisições autenticadas por API key (a chave trafega em texto no header). Atrás de proxy reverso que
    /// termina o TLS, configure <c>UseForwardedHeaders</c>. Padrão: <c>true</c>; desligado automaticamente em Development.
    /// </summary>
    public bool ApiKeyRequiresHttps { get; set; } = true;

    internal void Validate()
    {
        if (MaxTokenLength is < 1024 or > 256 * 1024)
            throw new InvalidOperationException("SecurityAspNetCoreOptions.MaxTokenLength deve ficar entre 1024 e 262144.");

        if (HubPaths.Any(p => !p.HasValue || p.Value == "/"))
            throw new InvalidOperationException("SecurityAspNetCoreOptions.HubPaths: informe caminhos específicos (ex.: /hubs/chat), nunca '/'.");
    }
}
