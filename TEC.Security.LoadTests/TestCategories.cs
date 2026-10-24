namespace TEC.Security.LoadTests;

/// <summary>Categorias dos testes deste projeto, num único lugar (usadas nos filtros <c>[Category=...]</c> do CI).</summary>
public static class TestCategories
{
    /// <summary>Concorrência e fumaça de carga (segundos): rodam no PR e no release, junto dos unitários (ci.yml e release.yml).</summary>
    public const string LoadCi = "Carga-CI";

    /// <summary>Soak, volume e carga sustentada (minutos): <c>[Explicit]</c>, rodam só no performance.yml (manual).</summary>
    public const string LoadHeavy = "Carga-Pesada";
}
