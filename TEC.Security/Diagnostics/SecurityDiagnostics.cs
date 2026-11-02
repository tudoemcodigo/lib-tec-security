using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace TEC.Security.Diagnostics;

/// <summary>Rastreamento e métricas (OpenTelemetry) do componente de segurança.</summary>
/// <remarks>
/// Segurança: nenhum trace ou métrica leva token, id de usuário, nome ou e-mail (traces e métricas costumam ir para terceiros).
/// As dimensões são de baixa cardinalidade: esquema, motivo e resultado. Exportados sem configuração pelo
/// <c>AddTecObservability</c> do TEC.Observability (prefixo <c>TEC.*</c>).
/// </remarks>
/// <example>
/// <code>
/// // Sem o TEC.Observability:
/// builder.Services.AddOpenTelemetry()
///     .WithTracing(t => t.AddSource(SecurityDiagnostics.ActivitySourceName))
///     .WithMetrics(m => m.AddMeter(SecurityDiagnostics.MeterName));
/// </code>
/// </example>
public static class SecurityDiagnostics
{
    /// <summary>Nome do <see cref="System.Diagnostics.ActivitySource"/> (obtenção de tokens de serviço).</summary>
    public const string ActivitySourceName = "TEC.Security";

    /// <summary>
    /// Nome do <see cref="System.Diagnostics.Metrics.Meter"/>. Instrumentos:
    /// <list type="bullet">
    /// <item><description><see cref="TecAuthenticationFailuresName"/> (contador): autenticações recusadas, com <c>security.scheme</c> e
    /// <c>security.reason</c> (<c>token</c>, <c>identity</c>, <c>tenant</c>, <c>permission_store</c>, <c>api_key</c>).</description></item>
    /// <item><description><see cref="TecAuthorizationDeniedName"/> (contador): acessos negados (HTTP 403), com <c>security.scheme</c> e
    /// <c>security.reason</c> (<c>permission</c>, <c>role</c>, <c>scope</c>, <c>kind</c>, <c>scheme</c>).</description></item>
    /// <item><description><see cref="TecTokenAcquisitionDurationName"/> (histograma, segundos): obtenção de tokens de serviço, com
    /// <c>security.provider</c>, <c>security.cache</c> (<c>hit</c>/<c>miss</c>) e, em falha, <c>error.type</c>.</description></item>
    /// <item><description><see cref="TecCircuitStateChangesName"/> (contador): mudanças de estado do circuit breaker, com
    /// <c>security.provider</c> e <c>security.circuit.state</c> (<c>open</c>, <c>half_open</c>, <c>closed</c>).</description></item>
    /// </list>
    /// </summary>
    public const string MeterName = "TEC.Security";

    /// <summary>Contador de autenticações recusadas (nome da convenção CMP-OBS-06).</summary>
    public const string TecAuthenticationFailuresName = "tec.security.authentication.failures";

    /// <summary>Contador de acessos negados (nome da convenção CMP-OBS-06).</summary>
    public const string TecAuthorizationDeniedName = "tec.security.authorization.denied";

    /// <summary>Histograma da obtenção de tokens de serviço, em segundos (nome da convenção CMP-OBS-06).</summary>
    public const string TecTokenAcquisitionDurationName = "tec.security.token.acquisition.duration";

    /// <summary>Contador de mudanças de estado do circuit breaker (nome da convenção CMP-OBS-06).</summary>
    public const string TecCircuitStateChangesName = "tec.security.circuit.state_changes";

    internal const string SchemeTag = "security.scheme";
    internal const string ReasonTag = "security.reason";
    internal const string ProviderTag = "security.provider";
    internal const string CacheTag = "security.cache";
    internal const string ErrorTypeTag = "error.type";
    internal const string CircuitStateTag = "security.circuit.state";
    internal const string CircuitOpen = "open";
    internal const string CircuitHalfOpen = "half_open";
    internal const string CircuitClosed = "closed";

    internal static readonly ActivitySource ActivitySource = new(ActivitySourceName);

    internal static readonly Meter Meter = new(MeterName, typeof(SecurityDiagnostics).Assembly.GetName().Version?.ToString());

    private static readonly Counter<long> AuthenticationFailures = Meter.CreateCounter<long>(
        TecAuthenticationFailuresName, unit: "{failure}", description: "Autenticações recusadas.");

    private static readonly Counter<long> AuthorizationDenied = Meter.CreateCounter<long>(
        TecAuthorizationDeniedName, unit: "{denial}", description: "Acessos negados por falta de permissão.");

    private static readonly Histogram<double> TokenAcquisitionDuration = Meter.CreateHistogram<double>(
        TecTokenAcquisitionDurationName, unit: "s", description: "Duração da obtenção de tokens de serviço.");

    private static readonly Counter<long> CircuitStateChanges = Meter.CreateCounter<long>(
        TecCircuitStateChangesName, unit: "{change}", description: "Mudanças de estado do circuit breaker dos provedores de identidade.");

    /// <summary>Registra uma autenticação recusada. Uso pelos pacotes de provedor.</summary>
    public static void RecordAuthenticationFailure(string scheme, string reason)
    {
        var schemeTag = new KeyValuePair<string, object?>(SchemeTag, scheme);
        var reasonTag = new KeyValuePair<string, object?>(ReasonTag, reason);
        if (AuthenticationFailures.Enabled)
            AuthenticationFailures.Add(1, schemeTag, reasonTag);
    }

    /// <summary>Registra um acesso negado. Uso pelos pacotes de provedor.</summary>
    public static void RecordAuthorizationDenied(string? scheme, string reason)
    {
        var schemeTag = new KeyValuePair<string, object?>(SchemeTag, scheme ?? "none");
        var reasonTag = new KeyValuePair<string, object?>(ReasonTag, reason);
        if (AuthorizationDenied.Enabled)
            AuthorizationDenied.Add(1, schemeTag, reasonTag);
    }

    /// <summary>Registra a obtenção de um token de serviço. <paramref name="errorType"/> só em falha.</summary>
    public static void RecordTokenAcquisition(string provider, bool cacheHit, double seconds, string? errorType)
    {
        if (!TokenAcquisitionDuration.Enabled)
            return;

        var tags = new TagList
        {
            { ProviderTag, provider },
            { CacheTag, cacheHit ? "hit" : "miss" }
        };
        if (errorType is not null)
            tags.Add(ErrorTypeTag, errorType);
        TokenAcquisitionDuration.Record(seconds, tags);
    }

    /// <summary>Inicia a <c>Activity</c> de obtenção de token (ou <c>null</c> sem ouvinte). Uso pelos pacotes de provedor.</summary>
    public static Activity? StartTokenAcquisition(string provider)
    {
        var activity = ActivitySource.StartActivity("security.token.acquire", ActivityKind.Client);
        activity?.SetTag(ProviderTag, provider);
        return activity;
    }

    /// <summary>Registra uma mudança de estado do circuito.</summary>
    internal static void RecordCircuitState(string provider, string state)
    {
        var providerTag = new KeyValuePair<string, object?>(ProviderTag, provider);
        var stateTag = new KeyValuePair<string, object?>(CircuitStateTag, state);
        if (CircuitStateChanges.Enabled)
            CircuitStateChanges.Add(1, providerTag, stateTag);
    }
}
