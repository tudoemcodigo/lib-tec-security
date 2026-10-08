using System.Net;
using System.Security.Claims;
using FsCheck;
using FsCheck.Fluent;
using Microsoft.Extensions.Primitives;
using TEC.Core.Security;
using TEC.Security.Abstractions;
using TEC.Security.ApiKeys;
using TEC.Security.AspNetCore.Authentication;
using TEC.Security.AspNetCore.Authorization;
using TEC.Security.Claims;
using TEC.Security.Common;
using TEC.Security.Configuration;
using TEC.Security.Permissions;
using TEC.Security.Tenants;
using TEC.Security.Tests.Fakes;
using TEC.Security.Tokens;

namespace TEC.Security.Tests.Security.Fuzzing;

/// <summary>
/// Testes de propriedade (FsCheck) com entradas hostis geradas aleatoriamente. Cada propriedade roda centenas de casos;
/// em caso de falha, a mensagem traz o contraexemplo e a semente para reproduzir.
/// </summary>
public class FuzzingTests
{
    // ---------- Formatos aceitos (SecurityRules) ----------

    [Test]
    public void SecurityRules_MatchReferenceImplementation_AndNeverThrow()
    {
        static bool All(string s, Func<char, bool> allowed) => s.All(allowed);
        static bool NameChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or ':' or '/' or '-';

        Prop.ForAll(Gen.OneOf(Hostile.AnyText, Hostile.NearlyValidName).ToArbitrary(), value =>
        {
            bool name = value.Length is >= 1 and <= SecurityRules.MaxNameLength && All(value, NameChar);
            bool tenant = value.Length is >= 1 and <= 64 && char.IsAsciiLetterOrDigit(value[0]) && All(value, c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-');
            bool service = value.Length is >= 3 and <= 40 && (char.IsAsciiLetterLower(value[0]) || char.IsAsciiDigit(value[0]))
                           && All(value, c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-');
            bool userId = value.Length is >= 1 and <= SecurityRules.MaxUserIdLength && All(value, c => c is >= '!' and <= '~');

            if (SecurityRules.IsValidName(value) != name || SecurityRules.IsValidTenantId(value) != tenant
                || SecurityRules.IsValidServiceName(value) != service || SecurityRules.IsValidUserId(value) != userId)
            {
                throw new InvalidOperationException($"Divergência para {Hostile.Show(value)}: nome {name}, tenant {tenant}, serviço {service}, id {userId}");
            }
        }).Check(Hostile.Config(1_000));
    }

    [Test]
    public void SanitizeDisplayName_NeverReturnsControlCharsOrMoreThan256_AndIsIdempotent()
    {
        var gen = Gen.OneOf(Hostile.AnyText, Hostile.Text.Select(s => new string('x', 250) + s + "   "));

        Prop.ForAll(gen.ToArbitrary(), value =>
        {
            string? sanitized = SecurityRules.SanitizeDisplayName(value);
            if (sanitized is null)
                return;

            if (sanitized.Length > 256 || sanitized.Any(char.IsControl) || sanitized.Length == 0 || char.IsWhiteSpace(sanitized[0]))
                throw new InvalidOperationException($"Nome inseguro: {Hostile.Show(sanitized)}");
            // Corte em 256 pode deixar espaço no fim; a segunda passada apara, e a terceira não muda mais nada
            string? again = SecurityRules.SanitizeDisplayName(SecurityRules.SanitizeDisplayName(sanitized));
            if (again != SecurityRules.SanitizeDisplayName(sanitized))
                throw new InvalidOperationException($"Não idempotente: {Hostile.Show(sanitized)}");
        }).Check(Hostile.Config(500));
    }

    // ---------- API key ----------

    private static readonly GeneratedApiKey FuzzKey = ApiKeyGenerator.Generate("erp-contoso");

    private static ApiKeyValidator FuzzValidator()
    {
        var options = new ApiKeyOptions();
        options.Keys[FuzzKey.KeyId] = new ApiKeyDefinition { Hash = FuzzKey.Hash, ExpiresOn = DateTimeOffset.UtcNow.AddDays(1), Permissions = ["pedidos:ler"] };
        return new ApiKeyValidator(new TestOptionsMonitor<ApiKeyOptions>(options));
    }

    [Test]
    public void ApiKey_ArbitraryOrStructuredInput_NeverAccepted_NeverThrows()
    {
        var validator = FuzzValidator();
        const string base64Url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        // Chaves com a estrutura certa (prefixo, id cadastrado, 43 caracteres Base64Url) e segredo aleatório
        var structured =
            from id in Gen.Elements(FuzzKey.KeyId, "erp-contoso", "ERP-CONTOSO", "erp-contoso ", "outro-id", "")
            from secret in Gen.Elements(base64Url.ToCharArray()).ArrayOf(43)
            from prefix in Gen.Elements("tec_", "TEC_", "tec-", "")
            select $"{prefix}{id}_{new string(secret)}";

        Prop.ForAll(Gen.OneOf(Hostile.AnyText, structured).ToArbitrary(), presented =>
        {
            if (presented != FuzzKey.Key && validator.Validate(presented) is not null)
                throw new InvalidOperationException($"Chave forjada aceita: {Hostile.Show(presented)}");
        }).Check(Hostile.Config(1_000));
    }

    [Test]
    public void ApiKey_AnySingleEditOfAValidKey_IsRejected()
    {
        var validator = FuzzValidator();
        var edits =
            from kind in Gen.Choose(0, 4)
            from position in Gen.Choose(0, FuzzKey.Key.Length - 1)
            from c in Gen.Elements("Aa0-_ .\0\u017F\u212AzZ".ToCharArray())
            select (Kind: kind, Position: position, Char: c);

        Prop.ForAll(edits.ToArbitrary(), e =>
        {
            var key = FuzzKey.Key;
            string edited = e.Kind switch
            {
                0 => key[..e.Position] + e.Char + key[(e.Position + 1)..],          // troca
                1 => key[..e.Position] + e.Char + key[e.Position..],                // inserção
                2 => key[..e.Position] + key[(e.Position + 1)..],                   // remoção
                3 => key[..e.Position] + char.ToUpperInvariant(key[e.Position]) + key[(e.Position + 1)..],  // caixa
                _ => key + e.Char,                                                  // sufixo
            };

            if (edited != key && validator.Validate(edited) is not null)
                throw new InvalidOperationException($"Chave alterada aceita: {Hostile.Show(edited)}");
        }).Check(Hostile.Config(1_000));

        // Controle: a chave original continua aceita
        if (validator.Validate(FuzzKey.Key) is null)
            throw new InvalidOperationException("A chave original deveria ser aceita.");
    }

    [Test]
    public void ApiKey_GeneratedKeys_AlwaysParse_AndHashesNeverCollide()
    {
        var ids = Gen.Elements("abc", "erp-contoso", "a1-b2-c3", new string('z', 40), "0-0");
        var seen = new HashSet<string>(StringComparer.Ordinal);

        Prop.ForAll(ids.ToArbitrary(), id =>
        {
            var key = ApiKeyGenerator.Generate(id);
            if (!ApiKeyGenerator.TryParse(key.Key, out string parsedId, out string secret) || parsedId != id
                || ApiKeyGenerator.ComputeHash(secret) != key.Hash || ApiKeyGenerator.DecodeHash(key.Hash) is not { Length: 32 })
                throw new InvalidOperationException($"Chave gerada fora do formato: id {id}");
            if (!seen.Add(key.Hash) || key.ToString().Contains(secret, StringComparison.Ordinal))
                throw new InvalidOperationException("Hash repetido ou segredo exposto no ToString.");
        }).Check(Hostile.Config(500));
    }

    [Test]
    public void ApiKey_DecodeHash_ArbitraryInput_NeverThrows_AndOnly32Bytes()
    {
        var gen = Gen.OneOf(Hostile.AnyText, Gen.Elements("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+/=".ToCharArray()).ArrayOf(43).Select(c => new string(c)));

        Prop.ForAll(gen.ToArbitrary(), value =>
        {
            if (ApiKeyGenerator.DecodeHash(value) is { } bytes && bytes.Length != 32)
                throw new InvalidOperationException($"Hash com {bytes.Length} bytes aceito");
        }).Check(Hostile.Config(1_000));
    }

    // ---------- Normalização da identidade ----------

    private static readonly TestOptionsMonitor<TenantOptions> FuzzTenants = new(BuildTenants());

    private static TenantOptions BuildTenants()
    {
        var options = new TenantOptions();
        options.Items["contoso"] = new TenantDefinition { IdentityProviders = { ["Test"] = ["tid-contoso", "tid-S"] } };
        options.Items["inativo"] = new TenantDefinition { Enabled = false, IdentityProviders = { ["Test"] = ["tid-inativo"] } };
        return options;
    }

    [Test]
    public void IdentityFactory_HostileIdentity_NeverThrows_OutputAlwaysNormalized()
    {
        var store = new FakePermissionStore { Resolve = c => [.. c.Roles.Select(r => r + ":executar"), "tec_perm", "com espaço", "\n"] };
        var factory = new SecurityIdentityFactory(new ConfigurationTenantRegistry(FuzzTenants), store,
            new TestOptionsMonitor<SecurityOptions>(new SecurityOptions { RequireTenant = false }));

        var claimTypes = Gen.Elements("tec_uid", "TEC_PERM", "Tec_Tenant", "tec_kind", "tec_normalized", "tec_scheme", "tec_provider", "roles", "oid", "tid", "name", "tec\u017Fperm");
        var identities =
            from scheme in Gen.OneOf(Gen.Constant("Test"), Hostile.NearlyValidName, Hostile.Text)
            from provider in Gen.OneOf(Gen.Constant("Test"), Hostile.NearlyValidName)
            from userId in Gen.OneOf(Gen.Constant("usuario-1"), Hostile.AnyText)
            from kind in Gen.Elements(PrincipalKind.User, PrincipalKind.Application, PrincipalKind.System, PrincipalKind.Anonymous, (PrincipalKind)99)
            from tenantId in Gen.OneOf(Gen.Constant<string?>(null), Gen.Elements<string?>("contoso", "inativo", "CONTOSO", "outro"), Hostile.Text.Select(s => (string?)s))
            from external in Gen.OneOf(Gen.Constant<string?>(null), Gen.Elements<string?>("tid-contoso", "TID-CONTOSO", "tid-inativo", "tid-\u017F", "tid-s"), Hostile.Text.Select(s => (string?)s))
            from roles in Hostile.Names(20)
            from scopes in Hostile.Names(10)
            from permissions in Hostile.Names(10)
            from claims in Gen.Zip(claimTypes, Hostile.Text).ListOf()
            from name in Hostile.AnyText
            select new ExternalIdentity
            {
                Scheme = scheme,
                Provider = provider,
                UserId = userId,
                Kind = kind,
                TenantId = tenantId,
                ExternalTenantId = external,
                Name = name,
                ClientId = name,
                Roles = roles,
                Scopes = scopes,
                Permissions = permissions,
                SourceClaims = [.. claims.Select(c => new Claim(c.Item1, c.Item2))]
            };

        Prop.ForAll(identities.ToArbitrary(), identity =>
        {
            var result = factory.CreateAsync(identity).GetAwaiter().GetResult();
            if (result.IsFailure)
                return;

            var principal = result.Value;
            var user = new SecurityUser(principal);
            var normalized = principal.Identities.Single();
            string Fail(string what) => $"{what} — identidade {Hostile.Show(identity.UserId)}, kind {identity.Kind}, tenant {Hostile.Show(identity.TenantId)}/{Hostile.Show(identity.ExternalTenantId)}";

            if (identity.Kind is not (PrincipalKind.User or PrincipalKind.Application) || user.Kind != identity.Kind)
                throw new InvalidOperationException(Fail("tipo de identidade não permitido foi aceito"));
            if (!SecurityRules.IsValidUserId(user.Id) || user.Id != identity.UserId)
                throw new InvalidOperationException(Fail("id fora do formato"));
            if (user.Roles.Concat(user.Scopes).Concat(user.Permissions).Any(v => !SecurityRules.IsValidName(v)))
                throw new InvalidOperationException(Fail("papel/escopo/permissão fora do formato"));
            if (user.Roles.Count > SecurityRules.MaxItemsPerIdentity || user.Permissions.Count > SecurityRules.MaxItemsPerIdentity)
                throw new InvalidOperationException(Fail("excesso de itens"));
            if (identity.Kind == PrincipalKind.Application && user.Scopes.Count > 0)
                throw new InvalidOperationException(Fail("aplicação com escopo delegado"));
            if (user.TenantId is not (null or "contoso"))
                throw new InvalidOperationException(Fail($"tenant inesperado '{user.TenantId}'"));
            // Tenant só pelo cadastro: explícito "contoso" (qualquer caixa) ou id externo cadastrado (sem diferenciar maiúsculas, mas sem
            // equivalências Unicode como ſ = s)
            bool contosoExpected = string.Equals(identity.TenantId, "contoso", StringComparison.OrdinalIgnoreCase)
                                   || (identity.TenantId is null && identity.ExternalTenantId is { } ext
                                       && identity.Provider.Equals("Test", StringComparison.OrdinalIgnoreCase)
                                       && (ext.Equals("tid-contoso", StringComparison.OrdinalIgnoreCase) || ext.Equals("tid-S", StringComparison.OrdinalIgnoreCase)));
            if ((user.TenantId == "contoso") != contosoExpected)
                throw new InvalidOperationException(Fail($"tenant resolvido incorretamente: '{user.TenantId}'"));
            // Claims do provedor com prefixo reservado (qualquer caixa) nunca sobrevivem; os normalizados aparecem uma vez
            foreach (string type in new[] { TecClaimTypes.UserId, TecClaimTypes.Kind, TecClaimTypes.Scheme, TecClaimTypes.Provider, TecClaimTypes.Normalized })
            {
                if (normalized.FindAll(type).Count() != 1)
                    throw new InvalidOperationException(Fail($"claim {type} repetido ou ausente"));
            }

            // Papéis, escopos e permissões só vêm da identidade, do store e dos papéis: claims tec_* injetados não contam
            var storeGrants = user.Roles.Select(r => r + ":executar").Append("tec_perm");
            var allowedPermissions = identity.Permissions.Concat(storeGrants).Concat(user.Roles).ToHashSet(StringComparer.Ordinal);
            if (!user.Roles.IsSubsetOf(identity.Roles) || !user.Scopes.IsSubsetOf(identity.Scopes) || !user.Permissions.IsSubsetOf(allowedPermissions))
                throw new InvalidOperationException(Fail("papel, escopo ou permissão que não veio da identidade nem do store"));
            if (normalized.Claims.Any(c => TecClaimTypes.IsReserved(c.Type) && c.Type != c.Type.ToLowerInvariant()))
                throw new InvalidOperationException(Fail("claim reservado do provedor sobreviveu"));
            if (user.Name is { } displayName && (displayName.Any(char.IsControl) || displayName.Length > 256))
                throw new InvalidOperationException(Fail("nome de exibição inseguro"));
        }).Check(Hostile.Config(1_500));
    }

    [Test]
    public void TenantRegistry_ArbitraryLookups_NeverThrow_AndMatchOnlyRegisteredIds()
    {
        using var registry = new ConfigurationTenantRegistry(FuzzTenants);
        string[] registered = ["tid-contoso", "tid-S", "tid-inativo"];
        var lookups =
            from provider in Gen.OneOf(Gen.Elements("Test", "TEST", "test", "T\u0435st", "Test\n", ""), Hostile.Text)
            from external in Gen.OneOf(Gen.Elements("tid-contoso", "TID-CONTOSO", "tid-s", "tid-\u017F", "tid-\u212A", "tid-contoso\n", " tid-contoso", "tid-inativo"), Hostile.AnyText)
            select (Provider: provider, External: external);

        Prop.ForAll(lookups.ToArbitrary(), l =>
        {
            var tenant = registry.FindByExternalId(l.Provider, l.External);
            bool expected = l.Provider.Equals("Test", StringComparison.OrdinalIgnoreCase)
                            && registered.Any(id => id.Equals(l.External, StringComparison.OrdinalIgnoreCase));
            if ((tenant is not null) != expected)
                throw new InvalidOperationException($"{Hostile.Show(l.Provider)}/{Hostile.Show(l.External)} resolvido para '{tenant?.Id}'");
            _ = registry.Find(l.External);
            _ = registry.GetEnabledExternalIds(l.Provider);
        }).Check(Hostile.Config(1_000));
    }

    [Test]
    public void PermissionCacheKey_IsInjective_ForValidContexts()
    {
        var names = Gen.Elements("a", "b", "a:b", "a/b", "ab", "b:a", "x.y", "Test", "test");
        var contexts =
            from provider in names
            from scheme in names
            from userId in Gen.Elements("u", "u:1", "1", "a", "a!b")
            from tenant in Gen.Elements<string?>(null, "", "t1", "a")
            from kind in Gen.Elements(PrincipalKind.User, PrincipalKind.Application)
            from roles in names.ArrayOf().Select(r => r.Distinct().ToArray())
            select new PermissionContext(provider, scheme, userId, tenant, kind, roles);

        Prop.ForAll(Gen.Two(contexts).ToArbitrary(), pair =>
        {
            var (a, b) = pair;
            bool same = a.Provider == b.Provider && a.Scheme == b.Scheme && a.UserId == b.UserId && (a.TenantId ?? "") == (b.TenantId ?? "")
                        && a.Kind == b.Kind && a.Roles.Order().SequenceEqual(b.Roles.Order());
            if ((CachingPermissionStore.CreateKey(a) == CachingPermissionStore.CreateKey(b)) != same)
                throw new InvalidOperationException($"Chaves de cache ambíguas: {a} × {b}");
        }).Check(Hostile.Config(2_000));
    }

    // ---------- Codificação de policies e leitura de headers ----------

    [Test]
    public void TecPolicyName_RoundTrips_AndArbitraryNamesDecodeSafely()
    {
        var validNames = Gen.Elements("pedidos:ler", "a", "x/y", "api.read", "Gerente", "Test");
        var requirements =
            from p in validNames.ArrayOf().Select(a => a.Distinct().ToArray())
            from r in validNames.ArrayOf().Select(a => a.Distinct().ToArray())
            from s in validNames.ArrayOf().Select(a => a.Distinct().ToArray())
            from h in validNames.ArrayOf().Select(a => a.Distinct().ToArray())
            from k in Gen.Choose(1, 7)
            select new TecRequirement(p, r, s, h, (TecPrincipalKinds)k);

        Prop.ForAll(requirements.ToArbitrary(), requirement =>
        {
            var decoded = TecPolicyName.Decode(TecPolicyName.Encode(requirement));
            if (decoded is null || decoded.ToString() != requirement.ToString())
                throw new InvalidOperationException($"Ida e volta divergente: {requirement} → {decoded}");
        }).Check(Hostile.Config(500));

        var names = Gen.OneOf(Hostile.AnyText.Select(s => TecPolicyName.Prefix + s),
            Gen.Elements("p=", "|r=", "|s=", "|h=", "|k=", "1", "7", "8", "-1", "0", "2147483647", "a,b", "a b", "|", "=").ListOf().Select(parts => TecPolicyName.Prefix + string.Concat(parts)));
        Prop.ForAll(names.ToArbitrary(), name =>
        {
            var decoded = TecPolicyName.Decode(name);
            if (decoded is null)
                return;
            if (decoded.Permissions.Concat(decoded.Roles).Concat(decoded.Scopes).Concat(decoded.Schemes).Any(v => !SecurityRules.IsValidName(v))
                || (decoded.Kinds & TecPrincipalKinds.Any) == 0 || (decoded.Kinds & ~TecPrincipalKinds.Any) != 0)
                throw new InvalidOperationException($"Policy malformada aceita: {Hostile.Show(name)}");
        }).Check(Hostile.Config(1_000));
    }

    [Test]
    public void BearerHeader_ArbitraryValues_ParseSafely()
    {
        var headers = Gen.OneOf(
            Hostile.AnyText.Select(s => new StringValues(s)),
            Hostile.AnyText.Select(s => new StringValues("Bearer " + s)),
            Gen.Zip(Hostile.Text, Hostile.Text).Select(t => new StringValues(["Bearer " + t.Item1, "Bearer " + t.Item2])));

        Prop.ForAll(headers.ToArbitrary(), header =>
        {
            if (!TecSchemeSelector.TryGetBearer(header, out string token))
                return;
            if (header.Count != 1 || token.Length == 0 || token != token.Trim())
                throw new InvalidOperationException($"Header aceito incorretamente: {Hostile.Show(header.ToString())}");
        }).Check(Hostile.Config(1_000));
    }

    // ---------- Destino do token de serviço (SSRF) ----------

    [Test]
    public void ServiceTokenDestination_OnlyHttpsToTheExactAllowedHost()
    {
        var options = new AccessTokenHandlerOptions { Scopes = { "api://contoso/.default" }, AllowedHosts = { "api.contoso.com" } };
        using var handler = new AccessTokenHandler(new NeverCalledProvider(), options);
        var urls =
            from scheme in Gen.Elements("https://", "http://", "HTTPS://", "ftp://", "//", "https:/", "")
            from userInfo in Gen.Elements("", "user@", "user:senha@", "api.contoso.com@", "@")
            from host in Gen.Elements("api.contoso.com", "API.CONTOSO.COM", "api.contoso.com.", "api.contoso.com.atacante.test", "atacante.test",
                "api-contoso.com", "\u0430pi.contoso.com", "api.contoso.com%2eatacante.test", "api.contoso.com\\@atacante.test", "127.0.0.1",
                "[::1]", "xn--pi-7ld.contoso.com", "api.contoso.co\u217F", "api.contoso.com:443", "api.contoso.com:8443")
            from suffix in Gen.Elements("", "/", "/pedidos?x=1", "#@atacante.test", "/@atacante.test", "?@atacante.test", "\\@atacante.test")
            select scheme + userInfo + host + suffix;

        Prop.ForAll(urls.ToArbitrary(), url =>
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            {
                if (options.IsAllowedDestination(null))
                    throw new InvalidOperationException("null aceito");
                return;
            }

            bool allowed = options.IsAllowedDestination(uri);
            bool expected = uri.Scheme == Uri.UriSchemeHttps && uri.UserInfo.Length == 0
                            && uri.IdnHost.Equals("api.contoso.com", StringComparison.OrdinalIgnoreCase);
            if (allowed != expected || handler.IsAllowed(uri) != allowed)
                throw new InvalidOperationException($"{Hostile.Show(url)} → host '{uri.IdnHost}', permitido {allowed}, esperado {expected}");
        }).Check(Hostile.Config(1_500));
    }

    // ---------- Ponta a ponta: tokens e headers adulterados ----------

    [Test]
    public async Task Http_MutatedTokensAndHostileHeaders_NeverAuthorize_NeverServerError()
    {
        await using var app = await SecuredTestApp.StartAsync();
        string valid = app.ValidToken();
        string[] segments = valid.Split('.');
        string otherPayload = app.ValidToken(t => { t.Subject = "outro-usuario"; t.Roles.Add("Admin"); }).Split('.')[1];

        var mutations =
            from kind in Gen.Choose(0, 8)
            from position in Gen.Choose(0, valid.Length - 1)
            from text in Hostile.Text
            select (Kind: kind, Position: position, Text: text);

        Prop.ForAll(mutations.ToArbitrary(), m =>
        {
            string token = m.Kind switch
            {
                0 => valid[..m.Position] + (valid[m.Position] == 'A' ? 'B' : 'A') + valid[(m.Position + 1)..],
                1 => valid[..m.Position],
                2 => $"{segments[0]}.{otherPayload}.{segments[2]}",                  // payload trocado, assinatura original
                3 => $"{segments[0]}.{segments[1]}.",                                 // sem assinatura
                4 => $"{segments[0]}.{segments[1]}.{segments[2]}.{segments[2]}",      // segmento extra
                5 => valid + m.Text,
                6 => m.Text,
                7 => $"{segments[1]}.{segments[0]}.{segments[2]}",                    // cabeçalho e payload invertidos
                _ => valid.Replace('-', '+').Replace('_', '/'),                       // Base64 comum em vez de Base64Url
            };
            // Caracteres de controle em header são recusados pelo servidor HTTP antes de chegar ao TEC.Security
            token = new string([.. token.Where(c => c is >= ' ' and not '\u007F')]);

            using var request = new HttpRequestMessage(HttpMethod.Get, "/pedidos");
            request.Headers.TryAddWithoutValidation(m.Kind == 6 && m.Position % 2 == 0 ? "X-Api-Key" : "Authorization",
                m.Kind == 6 && m.Position % 2 == 0 ? token : "Bearer " + token);
            using var response = app.Client.SendAsync(request).GetAwaiter().GetResult();

            // O JwtBearerHandler extrai o token com Trim(): espaço Unicode nas pontas (U+0085, U+00A0, U+2028...) é descartado
            // e o token validado é o original. Mudança que não altera os bytes decodificados (ex.: bits de enchimento do último
            // caractere) também pode manter o token válido.
            string received = token.Trim();
            bool equivalent = received == valid || (response.StatusCode == HttpStatusCode.OK && Decoded(received) == Decoded(valid));
            if ((int)response.StatusCode >= 500 || (response.StatusCode == HttpStatusCode.OK && !equivalent))
                throw new InvalidOperationException($"Mutação {m.Kind} na posição {m.Position}: HTTP {(int)response.StatusCode}");
        }).Check(Hostile.Config(400));
    }

    private static string Decoded(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            return token;
        try
        {
            return string.Join('.', parts.Select(p => Convert.ToHexString(Convert.FromBase64String(
                p.Replace('-', '+').Replace('_', '/').PadRight(p.Length + (4 - p.Length % 4) % 4, '=')))));
        }
        catch (FormatException)
        {
            return token;
        }
    }

    private sealed class NeverCalledProvider : IAccessTokenProvider
    {
        public ValueTask<AccessToken> GetTokenAsync(IReadOnlyList<string> scopes, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("O provedor não deveria ser chamado.");
    }
}
