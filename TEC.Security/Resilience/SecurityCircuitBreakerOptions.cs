namespace TEC.Security.Resilience;

/// <summary>
/// Circuit breaker de um provedor de identidade: com o provedor fora do ar, as chamadas seguintes falham na hora (sem esperar
/// tempo limite e retentativas a cada uma) até o fim da pausa.
/// </summary>
/// <remarks>
/// O circuito abre quando, dentro de <see cref="SamplingDuration"/>, houve pelo menos <see cref="MinimumThroughput"/> chamadas e
/// a proporção de falhas chegou a <see cref="FailureRatio"/>. Fica aberto por <see cref="BreakDuration"/>; depois deixa passar uma
/// chamada de teste (meia-abertura): sucesso fecha o circuito, falha abre de novo.
/// </remarks>
public sealed class SecurityCircuitBreakerOptions
{
    /// <summary>Liga o circuit breaker. Padrão: <c>true</c>.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Proporção de falhas que abre o circuito (maior que 0, até 1). Padrão: 0,5.</summary>
    public double FailureRatio { get; set; } = 0.5;

    /// <summary>Mínimo de chamadas na janela para avaliar a proporção (2 a 10.000). Padrão: 10.</summary>
    public int MinimumThroughput { get; set; } = 10;

    /// <summary>Janela de amostragem (0,5 segundo a 1 hora). Padrão: 30 segundos.</summary>
    public TimeSpan SamplingDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Tempo com o circuito aberto antes da chamada de teste (0,5 segundo a 1 hora). Padrão: 30 segundos.</summary>
    public TimeSpan BreakDuration { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Confere os limites (só com <see cref="Enabled"/>).</summary>
    /// <param name="optionPrefix">Prefixo do nome da opção nas mensagens (ex.: "Entra ID (cliente): Resilience.CircuitBreaker").</param>
    /// <exception cref="InvalidOperationException">Valor fora do limite.</exception>
    public void Validate(string optionPrefix)
    {
        if (Enabled)
            ValidateValues(optionPrefix);
    }

    internal void ValidateValues(string optionPrefix)
    {
        if (double.IsNaN(FailureRatio) || FailureRatio is <= 0 or > 1)
            throw new InvalidOperationException($"{optionPrefix}.FailureRatio deve ser maior que 0 e no máximo 1.");
        if (MinimumThroughput is < 2 or > 10_000)
            throw new InvalidOperationException($"{optionPrefix}.MinimumThroughput deve estar entre 2 e 10.000.");
        if (SamplingDuration < TimeSpan.FromMilliseconds(500) || SamplingDuration > TimeSpan.FromHours(1))
            throw new InvalidOperationException($"{optionPrefix}.SamplingDuration deve estar entre 0,5 segundo e 1 hora.");
        if (BreakDuration < TimeSpan.FromMilliseconds(500) || BreakDuration > TimeSpan.FromHours(1))
            throw new InvalidOperationException($"{optionPrefix}.BreakDuration deve estar entre 0,5 segundo e 1 hora.");
    }
}
