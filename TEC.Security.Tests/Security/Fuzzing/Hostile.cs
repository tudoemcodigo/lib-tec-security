using FsCheck;
using FsCheck.Fluent;

namespace TEC.Security.Tests.Security.Fuzzing;

/// <summary>
/// Geradores de entradas hostis para fuzzing de identidade: pedaços que costumam quebrar validadores de formato e codificações
/// internas (separadores <c>\n | = , : / _</c>), o prefixo reservado <c>tec_</c> em várias caixas, caracteres de controle,
/// espaços e homógrafos Unicode, e letras com armadilhas de maiúsculas/minúsculas (<c>ſ</c> vira <c>S</c>, o sinal de Kelvin
/// vira <c>k</c>, <c>İ</c>/<c>ı</c> do turco).
/// </summary>
internal static class Hostile
{
    private static readonly string[] Tokens =
    [
        "a", "Z", "0", "9", "-", "_", ".", ":", "/", "|", "=", ",", ";", " ", "\t", "\r", "\n", "\r\n", "\0", "\u0085", "\u2028",
        "tec_", "TEC_", "Tec_", "tec_perm", "tec_tenant", "tec_kind", "tec_normalized", "System", "system:", "apikey:", "Bearer ",
        "\u017F", "\u212A", "\u0130", "\u0131", "\u00DF", "\uFB00", "\uFF41", "\uFF21", "\u0430", "\u0435", "\u200B", "\u200D", "\uFEFF", "\u202E", "\u00A0",
        "\uD83D\uDE00", "%0a", "%2e", "%00", "..", "../", "\\", "@", "#", "?", "*", "'", "\"", "<script>", "{", "}", "[", "]",
        "admin", "pedidos:ler", "clientes:escrever", "contoso", "11111111-1111-1111-1111-111111111111",
    ];

    /// <summary>Texto UTF-16 válido (sem surrogates isolados), de 0 a ~100 pedaços.</summary>
    public static Gen<string> Text { get; } = Gen.Elements(Tokens).ListOf().Select(string.Concat);

    /// <summary>Texto que pode conter surrogates isolados (UTF-16 inválido), como vem de entradas corrompidas.</summary>
    public static Gen<string> AnyText { get; } = Gen.OneOf(
        Text,
        Text.Select(s => s + "\uD800"),
        Text.Select(s => "\uDC00" + s),
        Gen.Elements(Tokens).ListOf().Select(parts => string.Join("\uD83D", parts)));

    /// <summary>Valores quase válidos: nomes no formato aceito, com chance de um pedaço hostil no meio ou nas pontas.</summary>
    public static Gen<string> NearlyValidName { get; } =
        from head in Gen.Elements("pedidos", "clientes", "Gerente", "api.read", "a", "x/y", "tec_role")
        from sep in Gen.Elements(":", ".", "/", "-", "_")
        from tail in Gen.Elements("ler", "escrever", "1", "")
        from hostile in Gen.OneOf(Gen.Constant(""), Gen.Constant(""), Gen.Elements(Tokens))
        from position in Gen.Choose(0, 2)
        select position switch
        {
            0 => hostile + head + sep + tail,
            1 => head + hostile + sep + tail,
            _ => head + sep + tail + hostile,
        };

    /// <summary>Lista de valores (papéis, escopos, permissões) mistos: válidos, quase válidos e hostis.</summary>
    public static Gen<string[]> Names(int maxCount) =>
        Gen.Choose(0, maxCount).SelectMany(n => Gen.OneOf(NearlyValidName, Text).ArrayOf(n));

    /// <summary>Configuração padrão: falha com o contraexemplo na mensagem; <paramref name="maxTest"/> casos por propriedade.</summary>
    public static Config Config(int maxTest = 300) => FsCheck.Config.QuickThrowOnFailure.WithMaxTest(maxTest).WithQuietOnSuccess(true);

    /// <summary>Texto visível no relatório de falha (caracteres de controle e invisíveis escapados).</summary>
    public static string Show(string? value) =>
        value is null ? "null" : string.Concat(value.Select(c => c is < ' ' or > '~' ? $"\\u{(int)c:X4}" : c.ToString()));
}
