using System.Text.RegularExpressions;

namespace TEC.Security.Common;

/// <summary>
/// Formatos aceitos para os valores que viram claims normalizados ou chaves de configuração. Todos os padrões terminam em
/// <c>\z</c> (não em <c>$</c>, que aceitaria uma quebra de linha final) e aceitam só ASCII.
/// </summary>
public static partial class SecurityRules
{
    /// <summary>Tamanho máximo de papel, escopo e permissão.</summary>
    public const int MaxNameLength = 128;

    /// <summary>Tamanho máximo do identificador da identidade.</summary>
    public const int MaxUserIdLength = 256;

    /// <summary>Quantidade máxima de papéis, escopos ou permissões por identidade (proteção contra tokens inflados).</summary>
    public const int MaxItemsPerIdentity = 512;

    /// <summary>Papel, escopo ou permissão: letras, dígitos e <c>_ . : / -</c>, de 1 a 128 caracteres (ex.: <c>clientes:escrever</c>).</summary>
    public static bool IsValidName(string? value) => value is not null && NamePattern().IsMatch(value);

    /// <summary>Id de tenant da aplicação: letras, dígitos e <c>_ . -</c>, de 1 a 64 caracteres, começando com letra ou dígito.</summary>
    public static bool IsValidTenantId(string? value) => value is not null && TenantPattern().IsMatch(value);

    /// <summary>Nome de serviço da identidade de sistema e id de API key: minúsculas, dígitos e hífen, de 3 a 40 caracteres.</summary>
    public static bool IsValidServiceName(string? value) => value is not null && ServiceNamePattern().IsMatch(value);

    /// <summary>Identificador de identidade: 1 a 256 caracteres ASCII visíveis (sem espaço nem caractere de controle).</summary>
    public static bool IsValidUserId(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > MaxUserIdLength)
            return false;

        foreach (char c in value)
        {
            if (c is < '!' or > '~')
                return false;
        }

        return true;
    }

    /// <summary>Tamanho máximo do nome de exibição.</summary>
    public const int MaxDisplayNameLength = 256;

    /// <summary>
    /// Nome de exibição: até <see cref="MaxDisplayNameLength"/> caracteres, sem caracteres de controle, separadores de linha ou
    /// parágrafo, controles de direção bidirecional (que invertem o texto exibido) nem surrogates soltos.
    /// </summary>
    /// <param name="value">Nome recebido do provedor (não confiável).</param>
    /// <returns>O nome sem espaços nas pontas (cortado sem partir um par de surrogates), ou <c>null</c> se vazio ou recusado.</returns>
    /// <remarks>Recusado por inteiro, em vez de limpo, para que um nome forjado não vire outro nome aparentemente legítimo.</remarks>
    public static string? SanitizeDisplayName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var trimmed = value.Trim();
        if (trimmed.Length > MaxDisplayNameLength)
        {
            int length = char.IsHighSurrogate(trimmed[MaxDisplayNameLength - 1]) ? MaxDisplayNameLength - 1 : MaxDisplayNameLength;
            trimmed = trimmed[..length].TrimEnd();
        }

        for (int i = 0; i < trimmed.Length; i++)
        {
            char c = trimmed[i];
            if (char.IsHighSurrogate(c) && i + 1 < trimmed.Length && char.IsLowSurrogate(trimmed[i + 1]))
            {
                i++;
                continue;
            }

            if (char.IsControl(c) || char.IsSurrogate(c) || IsUnsafeFormatting(c))
                return null;
        }

        return trimmed;
    }

    /// <summary>Separadores de linha/parágrafo e controles bidirecionais (U+2028, U+2029, U+200E/F, U+202A-202E, U+2066-2069).</summary>
    private static bool IsUnsafeFormatting(char c) =>
        c is '\u2028' or '\u2029' or '\u200E' or '\u200F' or (>= '\u202A' and <= '\u202E') or (>= '\u2066' and <= '\u2069');

    [GeneratedRegex(@"^[A-Za-z0-9_.:/\-]{1,128}\z", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}\z", RegexOptions.CultureInvariant)]
    private static partial Regex TenantPattern();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9\-]{2,39}\z", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceNamePattern();
}
