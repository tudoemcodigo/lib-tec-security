using System.Globalization;

namespace TEC.Security.LoadTests.Infrastructure;

/// <summary>
/// Parâmetros dos testes de carga (as categorias ficam em <see cref="TestCategories"/>) (mesmo padrão do TEC.Core). Os volumes e durações dos testes pesados podem ser
/// ajustados por variáveis de ambiente, sem recompilar (ex.: TEC_CARGA_SOAK_SEGUNDOS=600 para um soak de 10 minutos).
/// </summary>
public static class LoadSettings
{
    /// <summary>
    /// Chave de [NotInParallel] dos testes pesados (categoria <see cref="TestCategories.LoadHeavy"/>): rodam um de cada vez,
    /// porque medem memória e vazão do processo inteiro.
    /// </summary>
    public const string HeavyExclusiveKey = "carga-pesada-exclusiva";

    /// <summary>Duração do soak em processo (padrão 120 s).</summary>
    public static int SoakSeconds => GetInt("TEC_CARGA_SOAK_SEGUNDOS", 120);

    /// <summary>Duração da carga pesada na API protegida (padrão 60 s).</summary>
    public static int ApiSeconds => GetInt("TEC_CARGA_API_SEGUNDOS", 60);

    /// <summary>Requisições simultâneas na carga pesada da API (padrão 64).</summary>
    public static int ApiConcurrency => GetInt("TEC_CARGA_API_CONCORRENCIA", 64);

    /// <summary>Tenants no teste de volume do cadastro (padrão 100 mil).</summary>
    public static int Tenants => GetInt("TEC_CARGA_TENANTS", 100_000);

    /// <summary>Identidades distintas no teste de volume do cache de permissões (padrão 200 mil, 4× o limite do cache).</summary>
    public static int Identities => GetInt("TEC_CARGA_IDENTIDADES", 200_000);

    /// <summary>
    /// Pasta onde os testes gravam os relatórios em Markdown (o workflow de performance publica no resumo do CI).
    /// Sem a variável, os relatórios vão só para a saída do teste.
    /// </summary>
    public static string? ReportDirectory => Environment.GetEnvironmentVariable("TEC_CARGA_RELATORIOS");

    /// <summary>Escreve o relatório na saída do teste e, se configurado, em arquivo.</summary>
    public static void Report(string title, string body)
    {
        Console.WriteLine($"## {title}{Environment.NewLine}{body}");
        if (ReportDirectory is { Length: > 0 } directory)
        {
            Directory.CreateDirectory(directory);
            File.AppendAllText(Path.Combine(directory, "carga.md"), $"### {title}{Environment.NewLine}{Environment.NewLine}{body}{Environment.NewLine}");
        }
    }

    private static int GetInt(string name, int defaultValue) =>
        int.TryParse(Environment.GetEnvironmentVariable(name), NumberStyles.None, CultureInfo.InvariantCulture, out int value) && value > 0
            ? value
            : defaultValue;
}
