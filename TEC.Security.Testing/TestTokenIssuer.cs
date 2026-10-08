using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace TEC.Security.Testing;

/// <summary>Conteúdo de um token de teste.</summary>
public sealed class TestTokenDescriptor
{
    /// <summary>Identificador estável (claim <c>sub</c>). Padrão: GUID novo.</summary>
    public string Subject { get; set; } = Guid.NewGuid().ToString("D");

    /// <summary>Tenant no provedor (claim <c>tid</c>), resolvido pelo cadastro <c>Security:Tenants:*:IdentityProviders:Test</c>.</summary>
    public string? ExternalTenantId { get; set; }

    /// <summary>Nome de exibição (claim <c>name</c>).</summary>
    public string? Name { get; set; }

    /// <summary>Token de aplicação (sem usuário). Padrão: <c>false</c>.</summary>
    public bool IsApplication { get; set; }

    /// <summary>Papéis (claim <c>roles</c>).</summary>
    public List<string> Roles { get; } = [];

    /// <summary>Escopos (claim <c>scp</c>; ignorados em token de aplicação).</summary>
    public List<string> Scopes { get; } = [];

    /// <summary>Claims extras (ex.: tentar injetar <c>tec_perm</c> em teste de segurança).</summary>
    public Dictionary<string, object> ExtraClaims { get; } = new(StringComparer.Ordinal);

    /// <summary>Validade. Padrão: 10 minutos.</summary>
    public TimeSpan Lifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Emissão (para testar token expirado ou ainda não válido). Padrão: agora.</summary>
    public DateTimeOffset? IssuedAt { get; set; }

    /// <summary>Audiência. Padrão: <see cref="TestTokenIssuer.Audience"/>.</summary>
    public string? Audience { get; set; }

    /// <summary>Emissor. Padrão: <see cref="TestTokenIssuer.Issuer"/>.</summary>
    public string? Issuer { get; set; }
}

/// <summary>
/// Emissor de tokens JWT para testes automatizados: par de chaves RSA gerado na memória do processo de teste (nunca gravado),
/// assinatura RS256. Registre o validador correspondente com <c>security.AddTestJwt(emissor)</c>.
/// </summary>
/// <example>
/// <code>
/// using var emissor = new TestTokenIssuer();
/// string token = emissor.CreateToken(t =&gt; { t.Roles.Add("pedidos:ler"); t.Scopes.Add("api.read"); });
/// client.DefaultRequestHeaders.Authorization = new("Bearer", token);
/// </code>
/// </example>
public sealed class TestTokenIssuer : IDisposable
{
    /// <summary>Emissor padrão.</summary>
    public const string DefaultIssuer = "https://emissor.tec-security.test/";

    /// <summary>Audiência padrão.</summary>
    public const string DefaultAudience = "api://tec-security-test";

    private readonly RSA _rsa = RSA.Create(2048);
    private readonly JsonWebTokenHandler _handler = new();
    private readonly TimeProvider _time;
    private volatile bool _disposed;

    /// <summary>Cria o emissor com chave nova.</summary>
    /// <param name="issuer">Emissor (claim <c>iss</c>).</param>
    /// <param name="audience">Audiência (claim <c>aud</c>).</param>
    /// <param name="time">Relógio da emissão (ex.: <c>FakeTimeProvider</c> nos testes); padrão <see cref="TimeProvider.System"/>.</param>
    /// <exception cref="ArgumentException">Emissor ou audiência vazios.</exception>
    public TestTokenIssuer(string issuer = DefaultIssuer, string audience = DefaultAudience, TimeProvider? time = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);
        Issuer = issuer;
        Audience = audience;
        _time = time ?? TimeProvider.System;
        SigningKey = new RsaSecurityKey(_rsa) { KeyId = Guid.NewGuid().ToString("N") };
    }

    /// <summary>Emissor dos tokens.</summary>
    public string Issuer { get; }

    /// <summary>Audiência dos tokens.</summary>
    public string Audience { get; }

    /// <summary>Chave pública/privada de assinatura.</summary>
    public SecurityKey SigningKey { get; }

    /// <summary>Cria um token assinado.</summary>
    /// <param name="configure">Ajusta o conteúdo do token (usuário, tenant, papéis, escopos, validade...).</param>
    /// <returns>JWT assinado com RS256.</returns>
    /// <exception cref="ObjectDisposedException">Emissor descartado.</exception>
    public string CreateToken(Action<TestTokenDescriptor>? configure = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var descriptor = new TestTokenDescriptor();
        configure?.Invoke(descriptor);

        var issuedAt = descriptor.IssuedAt ?? _time.GetUtcNow();
        var claims = new Dictionary<string, object>(StringComparer.Ordinal) { ["sub"] = descriptor.Subject };
        if (descriptor.ExternalTenantId is not null)
            claims["tid"] = descriptor.ExternalTenantId;
        if (descriptor.Name is not null)
            claims["name"] = descriptor.Name;
        if (descriptor.Roles.Count > 0)
            claims["roles"] = descriptor.Roles.ToArray();
        if (!descriptor.IsApplication && descriptor.Scopes.Count > 0)
            claims["scp"] = string.Join(' ', descriptor.Scopes);
        if (descriptor.IsApplication)
            claims["idtyp"] = "app";
        foreach (var (key, value) in descriptor.ExtraClaims)
            claims[key] = value;

        return _handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = descriptor.Issuer ?? Issuer,
            Audience = descriptor.Audience ?? Audience,
            Claims = claims,
            IssuedAt = issuedAt.UtcDateTime,
            NotBefore = issuedAt.UtcDateTime,
            Expires = issuedAt.Add(descriptor.Lifetime).UtcDateTime,
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256)
        });
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _disposed = true;
        _rsa.Dispose();
    }
}
