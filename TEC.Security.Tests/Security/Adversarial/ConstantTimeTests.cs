using System.Diagnostics;
using System.Globalization;
using TEC.Security.ApiKeys;
using TEC.Security.Configuration;
using TEC.Security.Tests.Fakes;

namespace TEC.Security.Tests.Security.Adversarial;

/// <summary>
/// Canais laterais de tempo: a validação de API key não pode variar de tempo conforme o id exista ou não (enumeração de ids)
/// nem conforme a posição em que o segredo apresentado difere do correto.
/// </summary>
/// <remarks>
/// O teste rápido (CI) compara medianas de lotes medidos em pares. Os testes estatísticos (estilo dudect: teste t de Welch
/// entre duas classes de entrada intercaladas aleatoriamente) são pesados e ruidosos: rodam sob demanda, na categoria
/// <see cref="TestCategories.SecurityHeavy"/> (veja docs/testes.md).
/// </remarks>
[NotInParallel(DosResistanceTests.TimingKey)]
public class ConstantTimeTests
{
    // Limite do |t| de Welch: acima disso há diferença de tempo detectável entre as classes (dudect usa 4,5 a 10)
    private const double LeakThreshold = 10;

    // Diferença relativa máxima entre as médias de id existente e inexistente (veja o teste)
    private const double MaxIdLookupDifference = 0.05;

    private static (ApiKeyValidator Validator, string Valid, string WrongSecret, string UnknownId) CreateValidator()
    {
        var options = new ApiKeyOptions();
        var key = ApiKeyGenerator.Generate("erp-contoso");
        options.Keys[key.KeyId] = new ApiKeyDefinition { Hash = key.Hash, ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) };
        for (int i = 0; i < 50; i++)
        {
            var other = ApiKeyGenerator.Generate($"sistema-{i:D2}");
            options.Keys[other.KeyId] = new ApiKeyDefinition { Hash = other.Hash, ExpiresOn = DateTimeOffset.UtcNow.AddDays(1) };
        }

        // Mesmo tamanho de id nas duas classes: só a existência do id muda
        string wrongSecret = key.Key[..^10] + (key.Key[^10] == 'A' ? 'B' : 'A') + key.Key[^9..];
        string unknown = ApiKeyGenerator.Generate("erp-ausente").Key;
        return (new ApiKeyValidator(new TestOptionsMonitor<ApiKeyOptions>(options)), key.Key, wrongSecret, unknown);
    }

    [Test]
    public async Task ApiKey_UnknownId_CostsTheSameAsWrongSecret()
    {
        var (validator, _, wrongSecret, unknownId) = CreateValidator();
        const int batch = 2_000;

        _ = Measure(() => validator.Validate(wrongSecret) is null, batch);
        // Medição em pares (um logo após o outro, em ordem alternada) e mediana das razões: ruído da máquina afeta os dois lados
        var ratios = new List<double>();
        for (int i = 0; i < 31; i++)
        {
            double existing, unknown;
            if (i % 2 == 0)
            {
                existing = Measure(() => validator.Validate(wrongSecret) is null, batch);
                unknown = Measure(() => validator.Validate(unknownId) is null, batch);
            }
            else
            {
                unknown = Measure(() => validator.Validate(unknownId) is null, batch);
                existing = Measure(() => validator.Validate(wrongSecret) is null, batch);
            }

            ratios.Add(unknown / existing);
        }

        // Limites largos de propósito (CI com processos em paralelo): pegam a regressão grosseira (ex.: recusar id
        // desconhecido antes de calcular e comparar o hash); a medição fina é a do teste pesado
        double ratio = Median(ratios);
        await Assert.That(ratio).IsBetween(0.5, 2.0).Because($"id desconhecido custa {ratio:F2}× o de um id existente (enumeração de ids por tempo)");
    }

    [Test]
    [Explicit]
    [Category(TestCategories.SecurityHeavy)]
    public async Task ApiKey_UnknownIdIsIndistinguishable_FromExistingIdWithWrongSecret()
    {
        var (validator, _, wrongSecret, unknownId) = CreateValidator();

        // O id não é segredo e a busca no Dictionary (acerto × falha no bucket) difere por natureza em poucos nanossegundos,
        // que o |t| acaba detectando com amostras suficientes. O que precisa ser igual é o trabalho caro (SHA-256 do segredo
        // e comparação em tempo constante): recusar o id desconhecido antes dele daria dezenas de por cento de diferença.
        // Por isso o critério aqui é o tamanho do efeito, não o |t|.
        var (t, difference) = WelchT(candidate => validator.Validate(candidate) is null, wrongSecret, unknownId);
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"API key id existente × inexistente: |t| = {Math.Abs(t):F2}, diferença das médias = {difference:P2} (limite {MaxIdLookupDifference:P0})"));

        await Assert.That(difference).IsLessThan(MaxIdLookupDifference);
    }

    [Test]
    [Explicit]
    [Category(TestCategories.SecurityHeavy)]
    public async Task ApiKey_SecretComparison_NoTimingDifference_BetweenEarlyAndLateMismatch()
    {
        var (validator, valid, _, _) = CreateValidator();
        int secretStart = valid.Length - 43;
        string early = valid[..secretStart] + (valid[secretStart] == 'A' ? 'B' : 'A') + valid[(secretStart + 1)..];
        string late = valid[..^10] + (valid[^10] == 'A' ? 'B' : 'A') + valid[^9..];

        double t = WelchT(candidate => validator.Validate(candidate) is null, early, late).T;
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"|t| API key segredo diferente no início × no fim = {Math.Abs(t):F2} (limite {LeakThreshold})"));

        await Assert.That(Math.Abs(t)).IsLessThan(LeakThreshold);
    }

    [Test]
    [Explicit]
    [Category(TestCategories.SecurityHeavy)]
    public async Task TimingDetector_DetectsANaiveComparison()
    {
        // Controle do método: uma comparação comum (que para no primeiro caractere diferente) precisa ser detectada,
        // senão um |t| baixo nos outros testes não prova nada
        var secret = new string('a', 32 * 1024);
        var earlyMismatch = "b" + secret[1..];
        var lateMismatch = secret[..^1] + "b";

        double t = WelchT(candidate => string.Equals(secret, candidate, StringComparison.Ordinal), earlyMismatch, lateMismatch).T;
        Console.WriteLine(string.Create(CultureInfo.InvariantCulture, $"|t| string.Equals (vulnerável) = {Math.Abs(t):F2}"));

        await Assert.That(Math.Abs(t)).IsGreaterThan(LeakThreshold);
    }

    private static double Measure(Func<bool> action, int batch)
    {
        long start = Stopwatch.GetTimestamp();
        for (int i = 0; i < batch; i++)
            _ = action();
        return Stopwatch.GetElapsedTime(start).TotalMilliseconds;
    }

    /// <summary>
    /// Teste t de Welch entre duas classes de entrada, sorteadas a cada amostra (estilo dudect). Cada amostra mede
    /// <paramref name="batch"/> chamadas; as amostras acima do percentil 90 são descartadas (interrupções do SO e do GC).
    /// </summary>
    /// <returns>O t de Welch e a diferença relativa entre as médias (|A − B| / maior média).</returns>
    /// <remarks>
    /// As duas classes passam pelo <b>mesmo</b> delegate e pelo mesmo laço: só a entrada muda. Delegates diferentes por
    /// classe são compilados em separado pelo JIT (nível de compilação e alinhamento de código próprios) e essa diferença
    /// aparece como falso vazamento. Cada entrada também é copiada 64 vezes em posições de memória sorteadas e usada em
    /// rodízio, para que o alinhamento dos dados (linhas de cache tocadas por comparações vetorizadas) não dependa da classe.
    /// </remarks>
    private static (double T, double RelativeDifference) WelchT(Func<string?, bool> operation, string? inputA, string? inputB, int samples = 40_000, int batch = 100)
    {
        const int copies = 64;
        var a = new List<double>(samples);
        var b = new List<double>(samples);
        // Random (não criptográfico) só sorteia a ordem das medições e as posições na memória, com semente fixa: sem uso
        // de segurança
#pragma warning disable CA5394
        var random = new Random(42);
        var poolA = new string?[copies];
        var poolB = new string?[copies];
        // Preenchimentos vivos até o fim: uma compactação do GC preserva os deslocamentos sorteados
        var padding = new List<byte[]>(copies * 2);
        for (int i = 0; i < copies; i++)
        {
            bool aFirst = random.Next(2) == 0;
            (aFirst ? poolA : poolB)[i] = Copy(aFirst ? inputA : inputB);
            (aFirst ? poolB : poolA)[i] = Copy(aFirst ? inputB : inputA);
        }

        for (int i = 0; i < 2_000; i++)
            _ = operation(poolA[i & (copies - 1)]) ^ operation(poolB[i & (copies - 1)]);

        int next = 0;
        for (int i = 0; i < samples; i++)
        {
            bool useA = random.Next(2) == 0;
            var pool = useA ? poolA : poolB;
            long start = Stopwatch.GetTimestamp();
            for (int j = 0; j < batch; j++)
                _ = operation(pool[next++ & (copies - 1)]);
            (useA ? a : b).Add(Stopwatch.GetTimestamp() - start);
        }

        GC.KeepAlive(padding);
        double cut = Percentile([.. a, .. b], 0.90);
        var croppedA = a.Where(x => x <= cut).ToArray();
        var croppedB = b.Where(x => x <= cut).ToArray();
        double meanA = croppedA.Average(), meanB = croppedB.Average();
        double varA = croppedA.Sum(x => (x - meanA) * (x - meanA)) / (croppedA.Length - 1);
        double varB = croppedB.Sum(x => (x - meanB) * (x - meanB)) / (croppedB.Length - 1);
        double denominator = Math.Sqrt(varA / croppedA.Length + varB / croppedB.Length);
        double t = denominator == 0 ? 0 : (meanA - meanB) / denominator;
        return (t, Math.Abs(meanA - meanB) / Math.Max(meanA, meanB));

        string? Copy(string? value)
        {
            padding.Add(new byte[random.Next(0, 8) * 8]);   // desloca a próxima alocação em 0 a 56 bytes
            return value is null ? null : new string(value.AsSpan());
        }
#pragma warning restore CA5394
    }

    private static double Median(List<double> values) => Percentile(values, 0.5);

    private static double Percentile(List<double> values, double fraction)
    {
        var sorted = values.Order().ToArray();
        return sorted[Math.Clamp((int)(fraction * sorted.Length), 0, sorted.Length - 1)];
    }
}
