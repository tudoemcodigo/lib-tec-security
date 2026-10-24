using System.Globalization;
using System.Text;
using TEC.Security.ApiKeys;
using TEC.Security.Testing;

namespace TEC.Security.LoadTests.Infrastructure;

/// <summary>
/// Cenários de carga da <see cref="SecuredApiHost"/>: tráfego legítimo (JWT de vários usuários, API key, endpoint público) e
/// tráfego hostil (tokens adulterados, expirados, de outra chave, <c>alg: none</c>, gigantes; API keys inválidas). Cada cenário
/// declara o status esperado: qualquer outro conta como erro.
/// </summary>
public static class SecurityScenarios
{
    /// <summary>Usuários distintos com o papel que concede a permissão (cada um normaliza e consulta o store uma vez).</summary>
    public const int Users = 500;

    /// <summary>Cenários legítimos.</summary>
    public static readonly string[] Legitimate = ["jwt-autorizado", "jwt-negado", "api-key", "publico"];

    /// <summary>Cenários de ataque (todos devem terminar em 401).</summary>
    public static readonly string[] Hostile =
        ["sem-credencial", "token-adulterado", "token-expirado", "token-outra-chave", "token-alg-none", "token-gigante", "api-key-invalida", "api-key-id-desconhecido"];

    /// <summary>Monta os cenários (tokens criados uma vez, antes da carga).</summary>
    public static IReadOnlyList<LoadScenario> Create(SecuredApiHost host)
    {
        var issuer = host.Issuer;
        string[] authorized = [.. Enumerable.Range(0, Users).Select(i => issuer.CreateToken(t =>
        {
            t.Subject = $"usuario-{i:D4}";
            t.ExternalTenantId = SecuredApiHost.Tid;
            t.Roles.Add("pedidos");
            t.Lifetime = TimeSpan.FromHours(2);
        }))];
        string[] denied = [.. Enumerable.Range(0, 50).Select(i => issuer.CreateToken(t =>
        {
            t.Subject = $"sem-papel-{i:D3}";
            t.ExternalTenantId = SecuredApiHost.Tid;
            t.Lifetime = TimeSpan.FromHours(2);
        }))];

        string expired = issuer.CreateToken(t => { t.ExternalTenantId = SecuredApiHost.Tid; t.Roles.Add("pedidos"); t.IssuedAt = DateTimeOffset.UtcNow.AddHours(-2); });
        using var other = new TestTokenIssuer(issuer.Issuer, issuer.Audience);
        string otherKey = other.CreateToken(t => { t.ExternalTenantId = SecuredApiHost.Tid; t.Roles.Add("pedidos"); t.Lifetime = TimeSpan.FromHours(2); });
        // Acima do MaxTokenLength do TEC.Security (16 KB) e abaixo do limite de headers do Kestrel (32 KB, que responderia 431)
        string huge = issuer.CreateToken(t => { t.ExternalTenantId = SecuredApiHost.Tid; t.ExtraClaims["enchimento"] = new string('x', 18_000); t.Lifetime = TimeSpan.FromHours(2); });
        string algNone = AlgNone(issuer.Issuer, issuer.Audience);
        string validKey = host.ApiKey.Key;
        string unknownKey = ApiKeyGenerator.Generate("id-desconhecido").Key;

        return
        [
            new("jwt-autorizado", 40, r => Bearer(HttpMethod.Get, "/pedidos", authorized[r.Next(authorized.Length)])),
            new("jwt-negado", 10, r => Bearer(HttpMethod.Get, "/pedidos", denied[r.Next(denied.Length)]), 403),
            new("api-key", 20, _ => ApiKey(validKey)),
            new("publico", 10, _ => new HttpRequestMessage(HttpMethod.Get, "/publico")),
            new("sem-credencial", 5, _ => new HttpRequestMessage(HttpMethod.Get, "/pedidos"), 401),
            new("token-adulterado", 5, r => Bearer(HttpMethod.Get, "/pedidos", Tamper(authorized[r.Next(authorized.Length)], r)), 401),
            new("token-expirado", 3, _ => Bearer(HttpMethod.Get, "/pedidos", expired), 401),
            new("token-outra-chave", 3, _ => Bearer(HttpMethod.Get, "/pedidos", otherKey), 401),
            new("token-alg-none", 2, _ => Bearer(HttpMethod.Get, "/pedidos", algNone), 401),
            new("token-gigante", 1, _ => Bearer(HttpMethod.Get, "/pedidos", huge), 401),
            new("api-key-invalida", 3, r => ApiKey(Tamper(validKey, r)), 401),
            new("api-key-id-desconhecido", 3, _ => ApiKey(unknownKey), 401),
        ];
    }

    /// <summary>
    /// Filtra e repondera os cenários: <c>"jwt-autorizado,api-key:5"</c> (nome ou nome:peso; sem peso, mantém o padrão).
    /// <c>null</c>, vazio ou <c>*</c> = todos.
    /// </summary>
    /// <exception cref="ArgumentException">Cenário desconhecido ou peso inválido.</exception>
    public static IReadOnlyList<LoadScenario> Select(IReadOnlyList<LoadScenario> all, string? selection)
    {
        if (string.IsNullOrWhiteSpace(selection) || selection.Trim() == "*")
            return all;

        var result = new List<LoadScenario>();
        foreach (string item in selection.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string[] parts = item.Split(':', 2);
            var scenario = all.FirstOrDefault(s => s.Name.Equals(parts[0], StringComparison.OrdinalIgnoreCase))
                           ?? throw new ArgumentException($"Cenário desconhecido: '{parts[0]}'.", nameof(selection));
            if (parts.Length == 2)
            {
                if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int weight) || weight < 1)
                    throw new ArgumentException($"Peso inválido no cenário '{parts[0]}'.", nameof(selection));
                scenario = scenario with { Weight = weight };
            }

            result.Add(scenario);
        }

        return result;
    }

    private static HttpRequestMessage Bearer(HttpMethod method, string path, string token)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        return request;
    }

    private static HttpRequestMessage ApiKey(string key)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/pedidos");
        request.Headers.TryAddWithoutValidation("X-Api-Key", key);
        return request;
    }

    /// <summary>
    /// Troca um caractere Base64Url (sempre por outro diferente) numa posição sorteada. Nunca o último caractere de um segmento:
    /// ali parte dos bits é enchimento, e a troca poderia decodificar para os mesmos bytes (token ainda válido).
    /// </summary>
    internal static string Tamper(string value, Random random)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        var chars = value.ToCharArray();
        int index;
        do
            index = random.Next(chars.Length - 1);
        while (alphabet.IndexOf(chars[index], StringComparison.Ordinal) < 0 || chars[index + 1] == '.');

        char replacement;
        do
            replacement = alphabet[random.Next(alphabet.Length)];
        while (replacement == chars[index]);

        chars[index] = replacement;
        return new string(chars);
    }

    private static string AlgNone(string issuer, string audience)
    {
        static string B64(string json) => Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        long exp = DateTimeOffset.UtcNow.AddHours(2).ToUnixTimeSeconds();
        return $$"""{{B64("""{"alg":"none","typ":"JWT"}""")}}.{{B64($$"""{"iss":"{{issuer}}","aud":"{{audience}}","sub":"x","tid":"{{SecuredApiHost.Tid}}","roles":["pedidos"],"exp":{{exp}}}""")}}.""";
    }
}
