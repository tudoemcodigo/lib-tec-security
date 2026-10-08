<div align="center">

<img src="https://raw.githubusercontent.com/tudoemcodigo/lib-tec-security/main/Images/Logo.png" alt="TEC.Security" width="100" />

# 🛡️ TEC.Security

**Núcleo do TEC.Security: identidade e permissões com uma única API para qualquer provedor de login, sem ASP.NET Core.**

[📚 Documentação](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/README.md) · [🐙 Repositório](https://github.com/tudoemcodigo/lib-tec-security)

</div>

## ✨ O que é

Usuário, tenant e permissões normalizados (`ISecurityUser`, que também é o `ICurrentUser` do TEC.Core, e `ICurrentTenant`),
cadastro de tenants com recarga (`ITenantRegistry`), papéis → permissões (`IPermissionStore`, com cache de uma consulta por
identidade), identidade de sistema e `RunAs` para workers (`ISecurityContext`), API keys guardadas só como hash
(`ApiKeyGenerator`, `ApiKeyValidator`), tokens de serviço anexados só aos hosts autorizados (`AccessTokenHandler`,
`CachingAccessTokenProvider`), erros padronizados (`SecurityErrors`) e telemetria sem dados pessoais.

## 🎯 Quando usar

- Vem junto com `TEC.Security.AspNetCore` e `TEC.Security.EntraId`: normalmente você instala o provedor.
- Sozinho em **workers, jobs e consumidores de fila** que precisam de identidade (sistema ou usuário da mensagem), tenants
  e permissões, sem ASP.NET Core.
- Para escrever uma biblioteca que recebe `ISecurityUser` ou um provedor de identidade novo.

## 📥 Instalação

```bash
dotnet nuget add source https://nuget.pkg.github.com/tudoemcodigo/index.json -n tec-interno -u <usuario> -p <PAT>
dotnet add package TEC.Security --version 0.0.1
```

O feed do GitHub Packages exige um PAT *classic* com `read:packages`. O pacote traz o `TEC.Core` junto.

## 🚀 Início rápido

```csharp
using TEC.Security.Abstractions;
using TEC.Security.DependencyInjection;

builder.Services.AddTecSecurity(builder.Configuration);   // lê a seção "Security" (tenants, permissões, API keys)

public sealed class FechamentoJob(ISecurityContext seguranca, IServiceScopeFactory scopes) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var sistema = await seguranca.CreateSystemPrincipalAsync("fechamento-mensal", tenantId: "contoso",
            cancellationToken: stoppingToken);
        if (sistema.IsFailure)
            return;   // SEGURANCA_ENTRADA_INVALIDA, SEGURANCA_TENANT_NAO_PERMITIDO...

        using (seguranca.RunAs(sistema.Value))
        {
            await using var scope = scopes.CreateAsyncScope();
            var usuario = scope.ServiceProvider.GetRequiredService<ISecurityUser>();
            // usuario.Id == "system:fechamento-mensal", usuario.TenantId == "contoso"
        }
    }
}
```

## 📚 Documentação

[Configuração](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/configuracao.md) ·
[Identidade e permissões](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/identidade-e-permissoes.md) ·
[Tenants](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/tenants.md) ·
[Workers](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/workers.md) ·
[API keys](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/api-keys.md) ·
[Erros](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/erros.md) ·
[Segurança](https://github.com/tudoemcodigo/lib-tec-security/blob/main/docs/seguranca.md)

`net8.0` e `net10.0` · Native AOT · [MIT](https://github.com/tudoemcodigo/lib-tec-security/blob/main/LICENSE) · Roberto Oliveira, equipe Tudo em Código
