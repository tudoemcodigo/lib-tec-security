using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using TEC.Core.IO;
using TEC.Core.Text.Codecs;
using TEC.Vault.Abstractions;
using TEC.Vault.Keys;

namespace TEC.Security.EntraId.Internal;

/// <summary>Autenticação do cliente no endpoint de token: segredo ou client assertion (JWT).</summary>
internal readonly record struct ClientAuthentication(string? Secret, string? Assertion)
{
    public override string ToString() => "ClientAuthentication { *** }";
}

/// <summary>
/// Credencial da aplicação no Entra ID, para os três usos: <see cref="TokenCredential"/> (client credentials via Azure.Identity),
/// autenticação do cliente na troca do código do login web e no On-Behalf-Of.
/// </summary>
/// <remarks>
/// <para>Nenhum valor secreto vem da configuração: certificado e segredo são lidos do TEC.Vault; as variantes federadas não têm
/// segredo nenhum.</para>
/// <para>Certificado: a client assertion é assinada com PS256 no próprio cofre (<see cref="IKeyCryptography.SignDataAsync"/>) e
/// identificada por <c>x5t#S256</c>; o certificado pode ser não exportável. O certificado (parte pública) é relido a cada 30
/// minutos, acompanhando a rotação no cofre.</para>
/// </remarks>
internal sealed class EntraIdClientCredential
{
    private static readonly TimeSpan MetadataLifetime = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan AssertionLifetime = TimeSpan.FromMinutes(5);

    private readonly EntraIdCloud _cloud;
    private readonly string? _tenantId;
    private readonly string? _clientId;
    private readonly EntraIdCredentialOptions _options;
    private readonly IServiceProvider _services;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private readonly Lazy<ManagedIdentityCredential> _managedIdentity;

    // Referências imutáveis trocadas por inteiro (volatile): leitura sem trava e sem valor "rasgado" entre threads
    private volatile CertificateInfo? _certificate;
    private volatile SecretInfo? _secret;

    public EntraIdClientCredential(EntraIdCloud cloud, string? tenantId, string? clientId, EntraIdCredentialOptions options,
        IServiceProvider services)
    {
        _cloud = cloud;
        _tenantId = tenantId;
        _clientId = clientId;
        _options = options;
        _services = services;
        _time = services.GetService<TimeProvider>() ?? TimeProvider.System;
        _managedIdentity = new Lazy<ManagedIdentityCredential>(() => new ManagedIdentityCredential(
            options.ManagedIdentityClientId is { } id ? ManagedIdentityId.FromUserAssignedClientId(id) : ManagedIdentityId.SystemAssigned));
    }

    public EntraIdCredentialType Type => _options.Type;

    /// <summary>Tipos que conseguem autenticar o cliente no endpoint de token (login web e On-Behalf-Of).</summary>
    public bool SupportsClientAuthentication => _options.Type is EntraIdCredentialType.Certificate or EntraIdCredentialType.ClientSecret
        or EntraIdCredentialType.ManagedIdentityFederation or EntraIdCredentialType.WorkloadIdentity;

    /// <summary>Validação na inicialização.</summary>
    public static void Validate(EntraIdCredentialOptions options, string? tenantId, string? clientId, IHostEnvironment? environment,
        bool requireClientAuthentication, string context)
    {
        void Require(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException($"{context}: {message}");
        }

        Require(Enum.IsDefined(options.Type), "Credential:Type inválido.");
        Require(options.ManagedIdentityClientId is null || EntraIdCloud.IsGuid(options.ManagedIdentityClientId), "ManagedIdentityClientId deve ser um GUID.");

        bool needsApp = options.Type is not (EntraIdCredentialType.ManagedIdentity or EntraIdCredentialType.Developer);
        Require(!needsApp || (EntraIdCloud.IsGuid(tenantId) && EntraIdCloud.IsGuid(clientId)), "TenantId e ClientId (GUIDs) são obrigatórios.");

        if (requireClientAuthentication)
        {
            Require(needsApp, "este fluxo exige credencial da app registration (ManagedIdentityFederation, WorkloadIdentity, Certificate ou ClientSecret).");
        }

        switch (options.Type)
        {
            case EntraIdCredentialType.Certificate:
                Require(!string.IsNullOrWhiteSpace(options.CertificateName), "Credential:CertificateName (nome no TEC.Vault) é obrigatório.");
                break;
            case EntraIdCredentialType.ClientSecret:
                Require(!string.IsNullOrWhiteSpace(options.ClientSecretName), "Credential:ClientSecretName (nome no TEC.Vault) é obrigatório.");
                break;
            case EntraIdCredentialType.Developer:
                Require(options.AllowDeveloperCredentialsOutsideDevelopment || environment?.IsDevelopment() == true,
                    "credencial Developer só é permitida no ambiente Development.");
                break;
        }
    }

    /// <summary>Credencial do Azure.Identity para client credentials.</summary>
    public TokenCredential CreateTokenCredential()
    {
        var authorityHost = _cloud.AuthorityHost;
        return _options.Type switch
        {
            EntraIdCredentialType.ManagedIdentity => _managedIdentity.Value,
            EntraIdCredentialType.WorkloadIdentity => new WorkloadIdentityCredential(new WorkloadIdentityCredentialOptions
            {
                TenantId = _tenantId,
                ClientId = _clientId,
                AuthorityHost = authorityHost
            }),
            EntraIdCredentialType.Developer => new ChainedTokenCredential(
                new AzureCliCredential(new AzureCliCredentialOptions { TenantId = _tenantId, AuthorityHost = authorityHost }),
                new AzureDeveloperCliCredential(new AzureDeveloperCliCredentialOptions { TenantId = _tenantId, AuthorityHost = authorityHost }),
                new VisualStudioCredential(new VisualStudioCredentialOptions { TenantId = _tenantId, AuthorityHost = authorityHost })),
            EntraIdCredentialType.ClientSecret => new SecretCredential(this, _tenantId!, _clientId!, authorityHost),
            _ => new ClientAssertionCredential(_tenantId!, _clientId!,
                ct => CreateAssertionAsync(_cloud.TokenEndpoint(_tenantId!), ct),
                new ClientAssertionCredentialOptions { AuthorityHost = authorityHost })
        };
    }

    /// <summary>Autenticação do cliente no endpoint de token <paramref name="tokenEndpoint"/>.</summary>
    public async Task<ClientAuthentication> GetClientAuthenticationAsync(string tokenEndpoint, CancellationToken cancellationToken) =>
        _options.Type == EntraIdCredentialType.ClientSecret
            ? new ClientAuthentication(await GetSecretAsync(cancellationToken).ConfigureAwait(false), null)
            : new ClientAuthentication(null, await CreateAssertionAsync(tokenEndpoint, cancellationToken).ConfigureAwait(false));

    private async Task<string> CreateAssertionAsync(string audience, CancellationToken cancellationToken) => _options.Type switch
    {
        EntraIdCredentialType.ManagedIdentityFederation => (await _managedIdentity.Value.GetTokenAsync(
            new TokenRequestContext([FederationAudience(_cloud) + "/.default"]), cancellationToken).ConfigureAwait(false)).Token,
        EntraIdCredentialType.WorkloadIdentity => await ReadFederatedTokenAsync(cancellationToken).ConfigureAwait(false),
        EntraIdCredentialType.Certificate => await CreateCertificateAssertionAsync(audience, cancellationToken).ConfigureAwait(false),
        _ => throw new InvalidOperationException("A credencial configurada não gera client assertion.")
    };

    /// <summary>Audiência do token da identidade gerenciada trocado por token da aplicação (federated identity credential).</summary>
    internal static string FederationAudience(EntraIdCloud cloud) => cloud.LoginHost switch
    {
        "login.microsoftonline.us" => "api://AzureADTokenExchangeUSGov",
        "login.chinacloudapi.cn" or "login.partner.microsoftonline.cn" => "api://AzureADTokenExchangeChina",
        _ => "api://AzureADTokenExchange"
    };

    /// <summary>Tamanho máximo do token federado lido de AZURE_FEDERATED_TOKEN_FILE.</summary>
    internal const int MaxFederatedTokenBytes = 16 * 1024;

    private static Task<string> ReadFederatedTokenAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string? path = Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE");
        if (string.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException("AZURE_FEDERATED_TOKEN_FILE não definido (Workload Identity).");

        return Task.FromResult(ReadFederatedToken(path));
    }

    /// <summary>Lê o token federado com teto de tamanho e UTF-8 estrito (arquivo pequeno, montado pelo orquestrador).</summary>
    internal static string ReadFederatedToken(string path)
    {
        if (!BoundedFileReader.TryReadUtf8(path, MaxFederatedTokenBytes, out string? text))
            throw new InvalidOperationException("Token federado grande demais.");

        string token = text.Trim();
        return token.Length > 0 ? token : throw new InvalidOperationException("Token federado vazio.");
    }

    // ---------------------------------------------------------------- certificado no cofre

    private sealed record CertificateInfo(string Version, string X5tS256, DateTimeOffset NotAfter, DateTimeOffset LoadedAt);

    private async Task<string> CreateCertificateAssertionAsync(string audience, CancellationToken cancellationToken)
    {
        var certificate = await GetCertificateAsync(cancellationToken).ConfigureAwait(false);
        var now = _time.GetUtcNow();
        if (certificate.NotAfter <= now)
            throw new InvalidOperationException("O certificado da aplicação no cofre está expirado.");

        string header = Base64UrlEncoder.Encode(WriteJson(w =>
        {
            w.WriteString("alg", "PS256");
            w.WriteString("typ", "JWT");
            w.WriteString("x5t#S256", certificate.X5tS256);
        }));
        string payload = Base64UrlEncoder.Encode(WriteJson(w =>
        {
            w.WriteString("aud", audience);
            w.WriteString("iss", _clientId);
            w.WriteString("sub", _clientId);
            w.WriteString("jti", Guid.NewGuid().ToString("D"));
            w.WriteNumber("iat", now.ToUnixTimeSeconds());
            w.WriteNumber("nbf", now.ToUnixTimeSeconds());
            w.WriteNumber("exp", now.Add(AssertionLifetime).ToUnixTimeSeconds());
        }));

        string signingInput = header + "." + payload;
        var crypto = _services.GetService<IKeyCryptography>()
                     ?? throw new InvalidOperationException("Credencial Certificate exige o TEC.Vault com chaves (AddTecVault + UseAzureKeyVault).");
        var signature = await crypto.SignDataAsync(_options.CertificateName!, Encoding.ASCII.GetBytes(signingInput),
            VaultSignatureAlgorithm.PS256, certificate.Version, cancellationToken).ConfigureAwait(false);
        if (signature.IsFailure)
            throw new InvalidOperationException($"O cofre recusou a assinatura da client assertion ({signature.Error?.Code}).");

        return signingInput + "." + Base64UrlEncoder.Encode(signature.Value.Signature);
    }

    private async Task<CertificateInfo> GetCertificateAsync(CancellationToken cancellationToken)
    {
        if (_certificate is { } cached && _time.GetUtcNow() - cached.LoadedAt < MetadataLifetime)
            return cached;

        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_certificate is { } current && _time.GetUtcNow() - current.LoadedAt < MetadataLifetime)
                return current;

            var reader = _services.GetService<ICertificateReader>()
                         ?? throw new InvalidOperationException("Credencial Certificate exige o TEC.Vault com certificados (AddTecVault + UseAzureKeyVault).");
            var result = await reader.GetCertificateAsync(_options.CertificateName!, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
                throw new InvalidOperationException($"Certificado da aplicação não encontrado no cofre ({result.Error?.Code}).");

            var vault = result.Value;
            if (vault.Version is not { Length: > 0 } version)
                throw new InvalidOperationException("Certificado da aplicação sem versão no cofre.");

            using var x509 = vault.ToX509Certificate();
            var info = new CertificateInfo(version, Base64UrlEncoder.Encode(SHA256.HashData(vault.Cer)), new DateTimeOffset(x509.NotAfter.ToUniversalTime()),
                _time.GetUtcNow());
            _certificate = info;
            return info;
        }
        finally
        {
            _lock.Release();
        }
    }

    // ---------------------------------------------------------------- segredo no cofre

    private sealed record SecretInfo(string Value, DateTimeOffset LoadedAt)
    {
        public override string ToString() => "SecretInfo { *** }";
    }

    private async Task<string> GetSecretAsync(CancellationToken cancellationToken)
    {
        if (_secret is { } cached && _time.GetUtcNow() - cached.LoadedAt < MetadataLifetime)
            return cached.Value;

        // Uma leitura no cofre por vez (sem stampede quando o segredo expira do cache sob carga)
        await _lock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_secret is { } current && _time.GetUtcNow() - current.LoadedAt < MetadataLifetime)
                return current.Value;

            var reader = _services.GetService<ISecretReader>()
                         ?? throw new InvalidOperationException("Credencial ClientSecret exige o TEC.Vault com segredos (AddTecVault + UseAzureKeyVault).");
            var result = await reader.GetSecretAsync(_options.ClientSecretName!, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (result.IsFailure)
                throw new InvalidOperationException($"Segredo da aplicação não encontrado no cofre ({result.Error?.Code}).");

            _secret = new SecretInfo(result.Value.Value, _time.GetUtcNow());
            return result.Value.Value;
        }
        finally
        {
            _lock.Release();
        }
    }

    /// <summary><see cref="ClientSecretCredential"/> com o segredo lido do cofre (e relido após a rotação).</summary>
    private sealed class SecretCredential(EntraIdClientCredential owner, string tenantId, string clientId, Uri authorityHost) : TokenCredential
    {
        private volatile CurrentCredential? _current;

        private sealed record CurrentCredential(string Secret, ClientSecretCredential Credential)
        {
            public override string ToString() => "CurrentCredential { *** }";
        }

        // API síncrona exigida pelo TokenCredential (o Azure.Identity usa a assíncrona; esta só atende quem chamar GetToken)
        public override Azure.Core.AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            GetTokenAsync(requestContext, cancellationToken).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<Azure.Core.AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            string secret = await owner.GetSecretAsync(cancellationToken).ConfigureAwait(false);
            var current = _current;
            if (current is null || !string.Equals(current.Secret, secret, StringComparison.Ordinal))
            {
                current = new CurrentCredential(secret, new ClientSecretCredential(tenantId, clientId, secret,
                    new ClientSecretCredentialOptions { AuthorityHost = authorityHost }));
                _current = current;
            }

            return await current.Credential.GetTokenAsync(requestContext, cancellationToken).ConfigureAwait(false);
        }
    }

    // ---------------------------------------------------------------- JSON

    private static byte[] WriteJson(Action<Utf8JsonWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }
}
