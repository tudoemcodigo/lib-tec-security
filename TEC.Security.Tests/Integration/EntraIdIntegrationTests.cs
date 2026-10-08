using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using TEC.Core.Common.Results;
using TEC.Vault.AzureKeyVault;
using TEC.Vault.DependencyInjection;
using TEC.Vault.InMemory;
using TEC.Security.Abstractions;
using TEC.Security.AspNetCore;
using TEC.Security.DependencyInjection;
using TEC.Security.EntraId;
using TEC.Security.Tests.Infrastructure;

namespace TEC.Security.Tests.Integration;

/// <summary>
/// Integração com o Entra ID e o Key Vault reais: a aplicação cliente obtém um token (client credentials, credencial guardada
/// no Key Vault de testes, com a client assertion assinada dentro do cofre, ou, com o cofre offline, no user-secrets) e chama
/// uma API protegida por <c>AddEntraIdApi</c>, validada com o JWKS real. Pula com o motivo sem configuração.
/// </summary>
/// <remarks>
/// <para>Configuração (variáveis de ambiente ou seção <c>TecTestes</c> do user-secrets/<c>appsettings.Local.json</c>):</para>
/// <list type="table">
/// <item><term>TenantId</term><description>Tenant do Entra ID (<c>TEC_TESTES_TENANT_ID</c>).</description></item>
/// <item><term>VaultUri</term><description>Key Vault de testes com a credencial da aplicação cliente (<c>TEC_TESTES_VAULT_URI</c>). Usado
/// primeiro, se estiver online e com o item.</description></item>
/// <item><term>Entra:ApiClientId</term><description>Client id da app registration da API (<c>TEC_TESTES_SECURITY_ENTRA_API_CLIENT_ID</c>).</description></item>
/// <item><term>Entra:ClientId</term><description>Client id da aplicação cliente (<c>TEC_TESTES_SECURITY_ENTRA_CLIENT_ID</c>).</description></item>
/// <item><term>Entra:CertificateName</term><description>Certificado da aplicação cliente no cofre, preferido
/// (<c>TEC_TESTES_SECURITY_ENTRA_CERTIFICATE_NAME</c>), ou...</description></item>
/// <item><term>Entra:ClientSecretName</term><description>...segredo da aplicação cliente no cofre
/// (<c>TEC_TESTES_SECURITY_ENTRA_CLIENT_SECRET_NAME</c>).</description></item>
/// <item><term>Entra:ClientSecret</term><description>Fallback com o cofre offline: o valor do segredo da aplicação cliente
/// (<c>TEC_TESTES_SECURITY_ENTRA_CLIENT_SECRET</c>), entregue ao TEC.Vault InMemory. Certificado não tem fallback: a assinatura
/// acontece no cofre (a chave privada não sai dele).</description></item>
/// <item><term>Entra:Role</term><description>App role da API atribuído à aplicação cliente (opcional; conferido nas permissões;
/// <c>TEC_TESTES_SECURITY_ENTRA_ROLE</c>).</description></item>
/// <item><term>Entra:AcceptV1</term><description><c>true</c> se a API ainda emite tokens v1 (<c>requestedAccessTokenVersion</c> nulo
/// no manifesto; <c>TEC_TESTES_SECURITY_ENTRA_ACCEPT_V1</c>).</description></item>
/// </list>
/// <para>O acesso ao cofre usa as credenciais do desenvolvedor (<c>az login</c>) ou, no CI, o login OIDC do Azure.</para>
/// </remarks>
[Category(TestCategories.Integration)]
public class EntraIdIntegrationTests
{
    private const string Prefix = "TEC_TESTES_SECURITY_ENTRA";

    /// <summary>Nome do segredo da aplicação cliente no cofre em memória (fallback), se <c>Entra:ClientSecretName</c> não for informado.</summary>
    private const string LocalSecretName = "entra-client-secret";

    [Test]
    public async Task Real_application_token_is_accepted_by_the_API_and_normalized()
    {
        var settings = await EntraSettings.LoadAsync();
        if (settings.SkipReason is { } reason)
        {
            Skip.Test(reason);
            return;
        }

        await using var app = await StartApiAsync(settings);
        var token = await app.Services.GetRequiredService<IAccessTokenProvider>()
            .GetTokenAsync([$"api://{settings.ApiClientId}/.default"], CancellationToken.None);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        var response = await app.Client.SendAsync(request);
        string body = await response.Content.ReadAsStringAsync();

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await Assert.That(body).StartsWith($"Application|{settings.ClientId}|{settings.TenantId}".ToLowerInvariant(), StringComparison.OrdinalIgnoreCase);
        if (settings.Role is not null)
            await Assert.That(body).Contains(settings.Role);
        await Assert.That(app.Logs.All).DoesNotContain(token.Token);
    }

    [Test]
    public async Task Real_token_issued_for_another_audience_is_rejected()
    {
        var settings = await EntraSettings.LoadAsync();
        if (settings.SkipReason is { } reason)
        {
            Skip.Test(reason);
            return;
        }

        await using var app = await StartApiAsync(settings);

        // Token legítimo, assinado pelo mesmo Entra ID e do mesmo tenant, mas para o Microsoft Graph: a API precisa recusar
        var token = await app.Services.GetRequiredService<IAccessTokenProvider>()
            .GetTokenAsync(["https://graph.microsoft.com/.default"], CancellationToken.None);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        var response = await app.Client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(app.Logs.All).DoesNotContain(token.Token);
    }

    private static Task<TestApp> StartApiAsync(EntraSettings settings) => TestApp.StartAsync(
        builder =>
        {
            builder.Services.AddTecVault(vault =>
            {
                if (settings.VaultUri is not null)
                    vault.UseAzureKeyVault(o =>
                    {
                        o.VaultUri = settings.VaultUri;
                        o.TenantId = settings.TenantId;
                        o.Authentication = AzureKeyVaultAuthentication.Developer;
                        o.AllowDeveloperCredentialsOutsideDevelopment = true;
                    });
                else
                    vault.UseInMemory(o =>
                    {
                        o.AllowOutsideDevelopment = true;
                        o.InitialSecrets[settings.SecretName!] = settings.LocalSecret!;
                    });
            });

            builder.Services.AddTecSecurity(builder.Configuration, security => security
                .AddAspNetCore()
                .AddEntraIdApi("Entra", o =>
                {
                    o.TenantId = settings.TenantId;
                    o.ClientId = settings.ApiClientId;
                    o.AcceptV1Tokens = settings.AcceptV1;
                    o.AllowedClientApplications.Add(settings.ClientId!);
                })
                .AddEntraIdClient(o =>
                {
                    o.TenantId = settings.TenantId;
                    o.ClientId = settings.ClientId;
                    o.Credential = settings.CertificateName is not null
                        ? new EntraIdCredentialOptions { Type = EntraIdCredentialType.Certificate, CertificateName = settings.CertificateName }
                        : new EntraIdCredentialOptions { Type = EntraIdCredentialType.ClientSecret, ClientSecretName = settings.SecretName };
                }));
        },
        app => app.MapGet("/me", (ISecurityUser u) => $"{u.Kind}|{u.ClientId}|{u.ExternalTenantId}|{string.Join(',', u.Permissions)}"),
        environment: "Development");

    /// <summary>Configuração lida uma vez por teste; <see cref="SkipReason"/> explica o que falta.</summary>
    private sealed record EntraSettings(
        string? TenantId, string? ApiClientId, string? ClientId, string? Role, bool AcceptV1,
        Uri? VaultUri, string? CertificateName, string? SecretName, string? LocalSecret, string? SkipReason)
    {
        public static async Task<EntraSettings> LoadAsync()
        {
            string? tenantId = TestSettings.TenantId(null);
            string? apiClientId = Setting("ApiClientId", "API_CLIENT_ID");
            string? clientId = Setting("ClientId", "CLIENT_ID");
            string? certificateName = Setting("CertificateName", "CERTIFICATE_NAME");
            string? secretName = Setting("ClientSecretName", "CLIENT_SECRET_NAME");
            string? role = Setting("Role", "ROLE");
            bool acceptV1 = Setting("AcceptV1", "ACCEPT_V1") is "true" or "True";

            if (tenantId is null || apiClientId is null || clientId is null)
            {
                return new EntraSettings(tenantId, apiClientId, clientId, role, acceptV1, null, null, null, null,
                    $"Integração Entra ID não configurada: defina {TestSettings.TenantIdVariable}, {Prefix}_API_CLIENT_ID e {Prefix}_CLIENT_ID " +
                    $"(ou TenantId, Entra:ApiClientId e Entra:ClientId na seção {TestSettings.Section} do user-secrets).");
            }

            // Primeiro o Key Vault de testes (online e com a credencial da aplicação cliente); senão, o segredo local (user-secrets)
            var (vaultUri, vaultReason) = await OnlineVaultAsync(tenantId, certificateName, secretName);
            string? localSecret = vaultUri is null ? Setting("ClientSecret", "CLIENT_SECRET") : null;
            if (vaultUri is null && localSecret is null)
            {
                return new EntraSettings(tenantId, apiClientId, clientId, role, acceptV1, null, null, null, null,
                    $"Sem credencial da aplicação cliente (Key Vault: {vaultReason} Segredo local: defina {Prefix}_CLIENT_SECRET ou " +
                    $"'dotnet user-secrets set {TestSettings.Section}:Entra:ClientSecret <segredo> --id {TestSettings.UserSecretsId}').");
            }

            if (localSecret is not null)
                (certificateName, secretName) = (null, secretName ?? LocalSecretName);

            return new EntraSettings(tenantId, apiClientId, clientId, role, acceptV1, vaultUri, certificateName, secretName, localSecret, null);
        }

        private static string? Setting(string key, string variableSuffix) =>
            TestSettings.Read([$"{Prefix}_{variableSuffix}"], [$"{TestSettings.Section}:Entra:{key}"]);
    }

    /// <summary>
    /// URI do Key Vault de testes se ele estiver configurado, acessível com as credenciais do desenvolvedor e com a credencial da
    /// aplicação cliente (certificado ou segredo); senão, <c>null</c> com o motivo.
    /// </summary>
    private static async Task<(Uri? VaultUri, string Reason)> OnlineVaultAsync(string tenantId, string? certificateName, string? secretName)
    {
        var vaultUri = TestSettings.VaultUri(null, out string reason);
        if (vaultUri is null)
            return (null, reason);
        if (certificateName is null && secretName is null)
            return (null, "Entra:CertificateName ou Entra:ClientSecretName não configurado.");

        void Configure(AzureKeyVaultOptions o)
        {
            o.VaultUri = vaultUri;
            o.TenantId = tenantId;
            o.Authentication = AzureKeyVaultAuthentication.Developer;
            o.AllowDeveloperCredentialsOutsideDevelopment = true;
        }

        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            Error? error = certificateName is not null
                ? (await AzureKeyVaultStores.CreateCertificateStore(Configure).GetCertificateAsync(certificateName, cancellationToken: timeout.Token)).Error
                : (await AzureKeyVaultStores.CreateSecretStore(Configure).GetSecretAsync(secretName!, cancellationToken: timeout.Token)).Error;
            return error is null
                ? (vaultUri, string.Empty)
                : (null, $"credencial da aplicação cliente indisponível em {vaultUri.Host} ({error.Code}; confira o item e o 'az login').");
        }
        catch (Exception exception) when (exception is OperationCanceledException or InvalidOperationException or ArgumentException)
        {
            return (null, $"{vaultUri.Host} inacessível ({exception.GetType().Name}).");
        }
    }
}
