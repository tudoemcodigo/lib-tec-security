using System.Diagnostics.Metrics;
using System.Reflection;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using TEC.Security.AspNetCore;
using TEC.Security.Diagnostics;
using TEC.Security.OpenIdConnect;
using TEC.Security.Resilience;

namespace TEC.Security.Tests;

/// <summary>
/// CMP-OBS-06/07: todo instrumento começa com <c>tec.security.</c> (corte limpo, ADR 0009 da Doutrina: os nomes <c>security.*</c>
/// não existem mais) e os EventIds do componente ficam na faixa 3000-3999.
/// </summary>
public class TelemetryConventionTests
{
    private const string Prefix = "tec.security.";

    private sealed record Measurement(string Instrument, double Value, Dictionary<string, object?> Tags);

    /// <summary>Escuta o Meter <c>TEC.Security</c> e guarda só as medições que carregam o marcador único do teste.</summary>
    private sealed class Capture : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly string _marker;
        private readonly object _gate = new();

        public List<Measurement> Measurements { get; } = [];
        public List<string> Instruments { get; } = [];

        public Capture(string marker)
        {
            _marker = marker;
            // Garante que o Meter e seus instrumentos existem antes de a escuta começar
            RuntimeHelpers.RunClassConstructor(typeof(SecurityDiagnostics).TypeHandle);
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name != SecurityDiagnostics.MeterName)
                    return;
                lock (_gate)
                    Instruments.Add(instrument.Name);
                listener.EnableMeasurementEvents(instrument);
            };
            _listener.SetMeasurementEventCallback<long>((i, v, t, _) => Add(i, v, t));
            _listener.SetMeasurementEventCallback<double>((i, v, t, _) => Add(i, v, t));
            _listener.Start();
        }

        private void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var dict = new Dictionary<string, object?>();
            foreach (var tag in tags)
                dict[tag.Key] = tag.Value;
            if (!dict.Values.Any(v => v is string s && s.Contains(_marker, StringComparison.Ordinal)))
                return; // medição de outro teste em paralelo
            lock (_gate)
                Measurements.Add(new Measurement(instrument.Name, value, dict));
        }

        public Measurement[] Of(string instrument)
        {
            lock (_gate)
                return Measurements.Where(m => m.Instrument == instrument).ToArray();
        }

        public void Dispose() => _listener.Dispose();
    }

    private static string Marker() => "t" + Guid.NewGuid().ToString("N");

    private static async Task<Measurement> AssertSingleMeasurementAsync(Capture capture, string name, double expectedValue,
        params string[] expectedTagKeys)
    {
        var measurements = capture.Of(name);
        await Assert.That(measurements.Length).IsEqualTo(1);
        await Assert.That(measurements[0].Value).IsEqualTo(expectedValue);
        // As tags não mudam: só as chaves esperadas, sem excesso
        await Assert.That(measurements[0].Tags.Keys.Order().ToArray()).IsEquivalentTo(expectedTagKeys.Order().ToArray());
        return measurements[0];
    }

    // ================================================================ Valor e tags dos instrumentos tec.security.*

    [Test]
    public async Task Authentication_failure_is_counted_with_scheme_and_reason()
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordAuthenticationFailure(marker, "token");

        var m = await AssertSingleMeasurementAsync(capture, "tec.security.authentication.failures", 1, "security.scheme", "security.reason");
        await Assert.That(m.Tags["security.scheme"]).IsEqualTo(marker);
        await Assert.That(m.Tags["security.reason"]).IsEqualTo("token");
    }

    [Test]
    public async Task Authorization_denied_is_counted_with_scheme_and_reason()
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordAuthorizationDenied(marker, "permission");

        var m = await AssertSingleMeasurementAsync(capture, "tec.security.authorization.denied", 1, "security.scheme", "security.reason");
        await Assert.That(m.Tags["security.reason"]).IsEqualTo("permission");
    }

    [Test]
    public async Task Authorization_denied_without_scheme_uses_none()
    {
        // Sem esquema o marcador vai no motivo; o valor do esquema tem de ser "none"
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordAuthorizationDenied(null, marker);

        var m = await AssertSingleMeasurementAsync(capture, "tec.security.authorization.denied", 1, "security.scheme", "security.reason");
        await Assert.That(m.Tags["security.scheme"]).IsEqualTo("none");
    }

    [Test]
    [Arguments(true, null)]
    [Arguments(false, "HttpRequestException")]
    public async Task Token_acquisition_duration_is_recorded_with_provider_cache_and_error_type(bool cacheHit, string? errorType)
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordTokenAcquisition(marker, cacheHit, 0.25, errorType);

        string[] keys = errorType is null
            ? ["security.provider", "security.cache"]
            : ["security.provider", "security.cache", "error.type"];
        var m = await AssertSingleMeasurementAsync(capture, "tec.security.token.acquisition.duration", 0.25, keys);
        await Assert.That(m.Tags["security.cache"]).IsEqualTo(cacheHit ? "hit" : "miss");
    }

    [Test]
    public async Task Circuit_state_changes_are_counted_with_provider_and_state()
    {
        string marker = Marker();
        using var capture = new Capture(marker);
        var circuit = new SecurityCircuitBreaker(marker, new SecurityCircuitBreakerOptions
        {
            MinimumThroughput = 2,
            FailureRatio = 0.5,
            BreakDuration = TimeSpan.FromSeconds(30)
        });

        for (int i = 0; i < 2; i++)
            await Assert.That(async () => await circuit.ExecuteAsync<int>(_ => throw new HttpRequestException("fora"), default))
                .Throws<HttpRequestException>();

        await Assert.That(circuit.IsOpen).IsTrue();
        var m = await AssertSingleMeasurementAsync(capture, "tec.security.circuit.state_changes", 1, "security.provider", "security.circuit.state");
        await Assert.That(m.Tags["security.circuit.state"]).IsEqualTo("open");
    }

    [Test]
    public async Task Repeated_failures_accumulate_in_the_single_instrument()
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        for (int i = 0; i < 7; i++)
            SecurityDiagnostics.RecordAuthenticationFailure(marker, "api_key");

        await Assert.That(capture.Of("tec.security.authentication.failures").Sum(m => m.Value)).IsEqualTo(7);
    }

    // ================================================================ Convenção CMP-OBS-06

    [Test]
    public async Task Meter_and_activity_source_names_do_not_change()
    {
        await Assert.That(SecurityDiagnostics.MeterName).IsEqualTo("TEC.Security");
        await Assert.That(SecurityDiagnostics.ActivitySourceName).IsEqualTo("TEC.Security");
    }

    [Test]
    public async Task Every_instrument_starts_with_tec_security_without_exception()
    {
        using var capture = new Capture(Marker());

        string[] published = capture.Instruments.ToArray();

        await Assert.That(published.Length).IsEqualTo(4);
        foreach (string name in published)
        {
            await Assert.That(name.StartsWith(Prefix, StringComparison.Ordinal)).IsTrue();
            await Assert.That(name).IsEqualTo(name.ToLowerInvariant());
        }
    }

    [Test]
    public async Task Legacy_instrument_names_no_longer_exist()
    {
        // ADR 0009 da Doutrina: corte limpo, sem coexistência
        string[] legacy =
        [
            "security.authentication.failures",
            "security.authorization.denied",
            "security.token.acquisition.duration",
            "security.circuit.state_changes"
        ];
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordAuthenticationFailure(marker, "token");
        SecurityDiagnostics.RecordAuthorizationDenied(marker, "permission");
        SecurityDiagnostics.RecordTokenAcquisition(marker, false, 0.1, null);

        await Assert.That(capture.Instruments.Intersect(legacy).ToArray()).IsEmpty();
        foreach (string name in legacy)
            await Assert.That(capture.Of(name)).IsEmpty();
    }

    [Test]
    public async Task Public_name_constants_all_follow_the_convention()
    {
        var constants = typeof(SecurityDiagnostics).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.Name.EndsWith("Name", StringComparison.Ordinal)
                && f.Name is not (nameof(SecurityDiagnostics.MeterName) or nameof(SecurityDiagnostics.ActivitySourceName)))
            .ToDictionary(f => f.Name, f => (string)f.GetRawConstantValue()!);

        await Assert.That(constants.Count).IsEqualTo(4);
        foreach (var (name, value) in constants)
        {
            await Assert.That(name.StartsWith("Tec", StringComparison.Ordinal)).IsTrue();
            await Assert.That(value.StartsWith(Prefix, StringComparison.Ordinal)).IsTrue();
        }
    }

    // ================================================================ Faixa de EventId (CMP-OBS-07): 3000-3999

    private static readonly Assembly[] ComponentAssemblies =
    [
        typeof(SecurityDiagnostics).Assembly,
        typeof(SecurityBuilderAspNetCoreExtensions).Assembly,
        typeof(OpenIdConnectExtensions).Assembly
    ];

    private static List<(string Origin, int Id)> CollectEventIds()
    {
        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;
        var found = new List<(string, int)>();
        foreach (var assembly in ComponentAssemblies)
        foreach (var type in assembly.GetTypes())
        {
            foreach (var method in type.GetMethods(all))
                if (method.GetCustomAttribute<LoggerMessageAttribute>() is { } attribute)
                    found.Add(($"{type.FullName}.{method.Name}", attribute.EventId));

            foreach (var field in type.GetFields(all))
            {
                if (field.FieldType == typeof(EventId) && field.IsStatic)
                    found.Add(($"{type.FullName}.{field.Name}", ((EventId)field.GetValue(null)!).Id));
                else if (field.IsLiteral && field.Name.Contains("EventId", StringComparison.OrdinalIgnoreCase) && field.FieldType == typeof(int))
                    found.Add(($"{type.FullName}.{field.Name}", (int)field.GetRawConstantValue()!));
            }
        }

        return found;
    }

    [Test]
    public async Task Every_event_id_of_the_component_is_in_range_3000_to_3999()
    {
        var ids = CollectEventIds();

        // Guarda contra passar no vazio: a varredura tem de enxergar os logs dos dois assemblies com eventos
        await Assert.That(ids.Count).IsGreaterThanOrEqualTo(20);
        await Assert.That(ids.Any(i => i.Origin.Contains("AspNetCoreSecurityLog", StringComparison.Ordinal))).IsTrue();
        await Assert.That(ids.Any(i => i.Origin.Contains(".SecurityLog.", StringComparison.Ordinal))).IsTrue();

        var outside = ids.Where(i => i.Id is < 3000 or > 3999).Select(i => $"{i.Origin}={i.Id}").ToArray();
        await Assert.That(outside).IsEmpty();
    }

    [Test]
    public async Task Event_ids_are_unique_within_the_component()
    {
        var duplicated = CollectEventIds().GroupBy(i => i.Id).Where(g => g.Count() > 1)
            .Select(g => $"{g.Key}: {string.Join(", ", g.Select(i => i.Origin))}").ToArray();

        await Assert.That(duplicated).IsEmpty();
    }
}
