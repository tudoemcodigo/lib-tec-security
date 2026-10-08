namespace TEC.Security.Tests;

/// <summary>Categorias dos testes deste projeto, num único lugar (usadas nos filtros <c>[Category=...]</c> do CI).</summary>
/// <remarks>
/// Sem categoria: unitários, regressão e segurança rápida (rodam em todo PR, em matriz). O CI seleciona por categoria, nunca
/// por namespace: unitários <c>/*/*/*/*[Category!=Integracao]</c>, integração <c>/*/*/*/*[Category=Integracao]</c> e pesados
/// <c>/*/*/*/*[Category=Seguranca-Pesada]</c>.
/// </remarks>
public static class TestCategories
{
    /// <summary>Dependências reais (Entra ID e Key Vault de testes): pulam com motivo quando o ambiente não está configurado.</summary>
    public const string Integration = "Integracao";

    /// <summary>Canais laterais de tempo (minutos): <c>[Explicit]</c>, rodam no release e no performance.yml.</summary>
    public const string SecurityHeavy = "Seguranca-Pesada";
}
