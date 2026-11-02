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
/// CMP-OBS-06/07: instrumentos <c>tec.security.*</c> (com o nome antigo <c>security.*</c> coexistindo por uma MINOR, mesma medição
/// e mesmas tags) e EventIds do componente na faixa 3000-3999.
/// </summary>
public class TelemetryConventionTests
{
    private const string NewPrefix = "tec.security.";
    private const string LegacyPrefix = "security.";

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

    private static async Task AssertSameMeasurementAsync(Capture capture, string newName, string legacyName, double expectedValue,
        params string[] expectedTagKeys)
    {
        var current = capture.Of(newName);
        var legacy = capture.Of(legacyName);
        await Assert.That(current.Length).IsEqualTo(1);
        await Assert.That(legacy.Length).IsEqualTo(1);
        await Assert.That(current[0].Value).IsEqualTo(expectedValue);
        await Assert.That(legacy[0].Value).IsEqualTo(expectedValue);
        // As tags não mudam: mesmas chaves (os nomes security.* atuais) e mesmos valores nos dois instrumentos
        await Assert.That(current[0].Tags.Keys.Order().ToArray()).IsEquivalentTo(expectedTagKeys.Order().ToArray());
        await Assert.That(legacy[0].Tags.Keys.Order().ToArray()).IsEquivalentTo(expectedTagKeys.Order().ToArray());
        foreach (var key in expectedTagKeys)
            await Assert.That(legacy[0].Tags[key]).IsEqualTo(current[0].Tags[key]);
    }

    // ================================================================ Coexistência novo + antigo

    [Test]
    public async Task Authentication_failure_is_emitted_by_new_and_legacy_instruments_with_same_tags()
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordAuthenticationFailure(marker, "token");

        await AssertSameMeasurementAsync(capture, "tec.security.authentication.failures", "security.authentication.failures", 1,
            "security.scheme", "security.reason");
        await Assert.That(capture.Of("tec.security.authentication.failures")[0].Tags["security.scheme"]).IsEqualTo(marker);
        await Assert.That(capture.Of("tec.security.authentication.failures")[0].Tags["security.reason"]).IsEqualTo("token");
    }

    [Test]
    public async Task Authorization_denied_is_emitted_by_new_and_legacy_instruments_with_same_tags()
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordAuthorizationDenied(marker, "permission");

        await AssertSameMeasurementAsync(capture, "tec.security.authorization.denied", "security.authorization.denied", 1,
            "security.scheme", "security.reason");
    }

    [Test]
    public async Task Authorization_denied_without_scheme_uses_none_in_both_instruments()
    {
        // Sem esquema o marcador vai no motivo; o valor do esquema ("none") tem de ser igual nos dois instrumentos
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordAuthorizationDenied(null, marker);

        await AssertSameMeasurementAsync(capture, "tec.security.authorization.denied", "security.authorization.denied", 1,
            "security.scheme", "security.reason");
        await Assert.That(capture.Of("security.authorization.denied")[0].Tags["security.scheme"]).IsEqualTo("none");
    }

    [Test]
    [Arguments(true, null)]
    [Arguments(false, "HttpRequestException")]
    public async Task Token_acquisition_duration_is_recorded_by_new_and_legacy_histograms_with_same_tags(bool cacheHit, string? errorType)
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        SecurityDiagnostics.RecordTokenAcquisition(marker, cacheHit, 0.25, errorType);

        string[] keys = errorType is null
            ? ["security.provider", "security.cache"]
            : ["security.provider", "security.cache", "error.type"];
        await AssertSameMeasurementAsync(capture, "tec.security.token.acquisition.duration", "security.token.acquisition.duration", 0.25, keys);
        await Assert.That(capture.Of("security.token.acquisition.duration")[0].Tags["security.cache"]).IsEqualTo(cacheHit ? "hit" : "miss");
    }

    [Test]
    public async Task Circuit_state_changes_are_emitted_by_new_and_legacy_instruments_with_same_tags()
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
        await AssertSameMeasurementAsync(capture, "tec.security.circuit.state_changes", "security.circuit.state_changes", 1,
            "security.provider", "security.circuit.state");
        await Assert.That(capture.Of("tec.security.circuit.state_changes")[0].Tags["security.circuit.state"]).IsEqualTo("open");
    }

    [Test]
    public async Task Repeated_failures_count_the_same_in_both_instruments()
    {
        string marker = Marker();
        using var capture = new Capture(marker);

        for (int i = 0; i < 7; i++)
            SecurityDiagnostics.RecordAuthenticationFailure(marker, "api_key");

        await Assert.That(capture.Of("tec.security.authentication.failures").Sum(m => m.Value)).IsEqualTo(7);
        await Assert.That(capture.Of("security.authentication.failures").Sum(m => m.Value)).IsEqualTo(7);
    }

    // ================================================================ Convenção CMP-OBS-06

    [Test]
    public async Task Meter_and_activity_source_names_do_not_change()
    {
        await Assert.That(SecurityDiagnostics.MeterName).IsEqualTo("TEC.Security");
        await Assert.That(SecurityDiagnostics.ActivitySourceName).IsEqualTo("TEC.Security");
    }

    [Test]
    public async Task Every_instrument_starts_with_tec_security_or_is_a_listed_legacy_name()
    {
        using var capture = new Capture(Marker());

        string[] published = capture.Instruments.ToArray();
        string[] current = published.Where(n => n.StartsWith(NewPrefix, StringComparison.Ordinal)).ToArray();
        string[] legacy = published.Except(current).ToArray();

        await Assert.That(current.Length).IsEqualTo(4);
        // O que não segue a convenção só pode ser o nome antigo de um instrumento novo (coexistência, remoção na 0.1.0)
        await Assert.That(legacy.Length).IsEqualTo(4);
        foreach (string name in legacy)
        {
            await Assert.That(name.StartsWith(LegacyPrefix, StringComparison.Ordinal)).IsTrue();
            await Assert.That(current).Contains("tec." + name);
        }
        foreach (string name in current)
            await Assert.That(name).IsEqualTo(name.ToLowerInvariant());
    }

    [Test]
    public async Task Public_name_constants_follow_the_convention_and_pair_with_the_legacy_ones()
    {
        var constants = typeof(SecurityDiagnostics).GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(f => f.IsLiteral && f.Name.EndsWith("Name", StringComparison.Ordinal)
                && f.Name is not (nameof(SecurityDiagnostics.MeterName) or nameof(SecurityDiagnostics.ActivitySourceName)))
            .ToDictionary(f => f.Name, f => (string)f.GetRawConstantValue()!);

        var tec = constants.Where(c => c.Key.StartsWith("Tec", StringComparison.Ordinal)).ToArray();
        await Assert.That(tec.Length).IsEqualTo(4);
        foreach (var (name, value) in tec)
        {
            await Assert.That(value.StartsWith(NewPrefix, StringComparison.Ordinal)).IsTrue();
            // Cada constante nova tem o par antigo (mesmo nome sem "Tec", valor sem o prefixo "tec.")
            await Assert.That(constants[name["Tec".Length..]]).IsEqualTo(value["tec.".Length..]);
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
