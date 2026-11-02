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
    /// Cada instrumento também é emitido com o nome antigo (<c>security.*</c>, obsoleto) até a 0.1.0, com as mesmas tags e medições.
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

    // Nomes antigos (sem o prefixo tec.security.). OBSOLETOS: coexistem com os novos por uma versão MINOR para não quebrar
    // dashboards e alertas dos consumidores; remoção prevista na 0.1.0 (2027-03-01). Não levam [Obsolete] para não gerar
    // aviso de compilação em quem só usa as constantes para assinar o Meter.

    /// <summary>OBSOLETO (remoção na 0.1.0): use <see cref="TecAuthenticationFailuresName"/>. Emitido em paralelo até lá.</summary>
    public const string AuthenticationFailuresName = "security.authentication.failures";

    /// <summary>OBSOLETO (remoção na 0.1.0): use <see cref="TecAuthorizationDeniedName"/>. Emitido em paralelo até lá.</summary>
    public const string AuthorizationDeniedName = "security.authorization.denied";

    /// <summary>OBSOLETO (remoção na 0.1.0): use <see cref="TecTokenAcquisitionDurationName"/>. Emitido em paralelo até lá.</summary>
    public const string TokenAcquisitionDurationName = "security.token.acquisition.duration";

    /// <summary>OBSOLETO (remoção na 0.1.0): use <see cref="TecCircuitStateChangesName"/>. Emitido em paralelo até lá.</summary>
    public const string CircuitStateChangesName = "security.circuit.state_changes";

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

    // Instrumentos com o nome antigo (OBSOLETOS, remoção na 0.1.0). Mesma unidade, mesmas tags, mesma medição.
    private static readonly Counter<long> LegacyAuthenticationFailures = Meter.CreateCounter<long>(
        AuthenticationFailuresName, unit: "{failure}", description: "OBSOLETO: use tec.security.authentication.failures.");

    private static readonly Counter<long> LegacyAuthorizationDenied = Meter.CreateCounter<long>(
        AuthorizationDeniedName, unit: "{denial}", description: "OBSOLETO: use tec.security.authorization.denied.");

    private static readonly Histogram<double> LegacyTokenAcquisitionDuration = Meter.CreateHistogram<double>(
        TokenAcquisitionDurationName, unit: "s", description: "OBSOLETO: use tec.security.token.acquisition.duration.");

    private static readonly Counter<long> LegacyCircuitStateChanges = Meter.CreateCounter<long>(
        CircuitStateChangesName, unit: "{change}", description: "OBSOLETO: use tec.security.circuit.state_changes.");

    /// <summary>Registra uma autenticação recusada. Uso pelos pacotes de provedor.</summary>
    public static void RecordAuthenticationFailure(string scheme, string reason)
    {
        var schemeTag = new KeyValuePair<string, object?>(SchemeTag, scheme);
        var reasonTag = new KeyValuePair<string, object?>(ReasonTag, reason);
        if (AuthenticationFailures.Enabled)
            AuthenticationFailures.Add(1, schemeTag, reasonTag);
        if (LegacyAuthenticationFailures.Enabled)
            LegacyAuthenticationFailures.Add(1, schemeTag, reasonTag);
    }

    /// <summary>Registra um acesso negado. Uso pelos pacotes de provedor.</summary>
    public static void RecordAuthorizationDenied(string? scheme, string reason)
    {
        var schemeTag = new KeyValuePair<string, object?>(SchemeTag, scheme ?? "none");
        var reasonTag = new KeyValuePair<string, object?>(ReasonTag, reason);
        if (AuthorizationDenied.Enabled)
            AuthorizationDenied.Add(1, schemeTag, reasonTag);
        if (LegacyAuthorizationDenied.Enabled)
            LegacyAuthorizationDenied.Add(1, schemeTag, reasonTag);
    }

    /// <summary>Registra a obtenção de um token de serviço. <paramref name="errorType"/> só em falha.</summary>
    public static void RecordTokenAcquisition(string provider, bool cacheHit, double seconds, string? errorType)
    {
        if (!TokenAcquisitionDuration.Enabled && !LegacyTokenAcquisitionDuration.Enabled)
            return;

        var tags = new TagList
        {
            { ProviderTag, provider },
            { CacheTag, cacheHit ? "hit" : "miss" }
        };
        if (errorType is not null)
            tags.Add(ErrorTypeTag, errorType);
        if (TokenAcquisitionDuration.Enabled)
            TokenAcquisitionDuration.Record(seconds, tags);
        if (LegacyTokenAcquisitionDuration.Enabled)
            LegacyTokenAcquisitionDuration.Record(seconds, tags);
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
        if (LegacyCircuitStateChanges.Enabled)
            LegacyCircuitStateChanges.Add(1, providerTag, stateTag);
    }
}
