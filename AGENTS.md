# Instruções para agentes — TEC.Security

Este arquivo complementa as instruções herdadas de `AGENT_BASE.md`. O TEC.Security implementa autenticação e autorização com uma única API para qualquer provedor de login: fechado por padrão, multi-tenant e sem segredos na aplicação.

## Escopo e segurança de alterações

- O escopo padrão é este repositório. Não altere outros repositórios `TEC.*`, não publique pacotes/tags/releases e não rode sincronizações que escrevam fora daqui sem pedido explícito.
- Antes de editar, confira `git status` e `git diff`. Preserve alterações não commitadas; não use reset, checkout destrutivo ou limpeza para descartar trabalho existente.
- Mudanças em APIs públicas (`ISecurityUser`, `ICurrentUser`, `ICurrentTenant`, `ISecurityContext`, `ITenantRegistry`, `IPermissionStore`, `IAccessTokenProvider`, `ISecurityUserFactory`), validação JWT endurecida, `[TecAuthorize]`, tenants, API keys, chamadas M2M ou alvos .NET exigem revisão de compatibilidade, documentação, changelog e consumidores.
- Testes devem atravessar contratos públicos e verificar resultados observáveis. Para mudanças de comportamento, cubra entradas inválidas, limites, falhas e concorrência quando aplicável.
- Trate todo dado externo como não confiável. Não exponha segredos, PII ou conteúdo controlado pelo usuário em exceções, logs, URLs ou sumários.
- Zero Trust: todo token validado por inteiro (algoritmos só RS*/PS*/ES*, emissor exato, audiência, tolerância 30s), claims `tec_*` do provedor descartados, tenant vem só do cadastro, respostas não revelam motivo da recusa, nenhum token/segredo/dado pessoal em log/trace/métrica.
- Fechado por padrão: sem atributo, exige identidade; `[TecAuthorize]` + `[AllowAnonymous]` impede a subida.
- Configuração errada ou insegura derruba a **subida**, não a primeira requisição.
- Client secret só via `TEC.Vault` (`ISecretReader`); token de serviço anexado só aos `AllowedHosts` com HTTPS.

## Mapa da implementação

- `TEC.Security/`: biblioteca multi-target (`net8.0` e `net10.0`), núcleo sem ASP.NET Core.
  - `Abstractions/`: `ISecurityUser`, `ICurrentUser`, `ICurrentTenant`, `ISecurityContext`, `ITenantRegistry`, `IPermissionStore`, `IAccessTokenProvider`, `ICachingAccessTokenProvider`, `SecurityErrors`, `TecClaimTypes`, `TecPrincipalKinds`.
  - `Authorization/`: `[TecAuthorize]`, `RequireTecAuthorization`, `FallbackPolicy` fechada, `IPermissionChecker`.
  - `Identity/`: `SecurityIdentityFactory` (descarta `tec_*`, tenant do cadastro, papéis → permissões), `ExternalIdentity`.
  - `ApiKeys/`: `ApiKeyGenerator`, hash SHA-256, limite de tentativas, rotação.
  - `Workers/`: `ISecurityContext.CreateSystemPrincipalAsync`, `RunAs`.
  - `Telemetry/`: `ActivitySource` e `Meter` `TEC.Security` da BCL; assinados pelo TEC.Observability via prefixo `TEC.*`.
- `TEC.Security.AspNetCore/`: escolha do provedor por requisição, JWT endurecido, `[TecAuthorize]`, policies fechadas, 401/403 padronizados (`ApiResponse` do TEC.Core), API key, login web, base para provedores.
- `TEC.Security.OpenIdConnect/`: OpenID Connect agnóstico (Keycloak, Auth0, Okta, Entra ID, Google, Cognito), M2M Client Credentials, login web com PKCE. Depende de `TEC.Vault` para segredo do cliente.
- `TEC.Security.Testing/`: emissor de tokens para testar a sua API, bloqueado fora de Development, Testing e Test.
- `TEC.Security.Tests/`: 190 testes unitários por TFM (TUnit + FsCheck: ponta a ponta, fuzzing, DoS, vazamento, tempo constante).
- `TEC.Security.LoadTests/`: 8 de carga rápida (`Carga-CI`), 3 `Seguranca-Pesada`, 6 `Carga-Pesada` sob demanda.
- `samples/`: exemplos de uso.
- `build/`: props/targets compartilhados.
- `docs/adr/`: decisões arquiteturais (identidade normalizada, fechado por padrão, permissões, tenants, API keys, tokens de serviço, workers, provedores).
- `docs/`: guias por configuração, autorização, identidade/permissões, tenants, provedor OIDC, Entra ID, chamadas entre serviços, API keys, workers, novo provedor, integrações TEC, observabilidade, erros, segurança, testes, desenvolvimento.

## Contratos relevantes

- `Directory.Build.props` é a fonte única de versão do pacote (uma versão para os quatro pacotes). A versão inicial é `0.0.1`; não introduza versões nos `.csproj`.
- `Directory.Packages.props` pode declarar versões distintas por TFM; condições por TFM são intencionais.
- Dependências TEC.* são declaradas com `<TecReference Include="..." />`, não com `PackageReference` direto.
- `ISecurityUser` implementa `ICurrentUser` do TEC.Core; a identidade normalizada chega aos outros componentes sem que eles dependam do TEC.Security.
- `TEC.Security.OpenIdConnect` depende de `TEC.Vault` para ler segredo do cliente (`ISecretReader`) do login web e chamadas entre serviços.
- Native AOT: ✅ `IsAotCompatible` em todos os pacotes (binding de configuração gerado em compilação, JSON do 401/403 com `JsonSerializerContext`, logs por source generator).
- Workflows dos consumidores chamam `tudoemcodigo/tec-workflows`; confira as tags realmente publicadas antes de alterar referências.
- A licença é Apache-2.0. Mantenha `LICENSE`, `NOTICE`, badge/README e `<PackageLicenseExpression>` coerentes; consulte `NOTICE` para atribuição.

## Documentação

- `README.md` e `CHANGELOG.md` têm conteúdo próprio do TEC.Security: siga o padrão do template, mantenha a marca Tudo em Código em todos os READMEs e não substitua o conteúdo específico por placeholders genéricos.
- Atualize `README.md`, `CHANGELOG.md` e os guias em `docs/` quando uma mudança alterar comportamento ou contrato.
- Registre decisões transversais em um ADR numerado e mantenha `docs/adr/README.md` e `docs/README.md` atualizados.
- Consulte `docs/revisao-tecnica.md` como relatório de auditoria com data e escopo; não trate resultados históricos como estado atual sem nova verificação.
- Workflows e configurações centrais do consumidor estão em `.github/workflows/`; mantenha `.github/workflows/README.md` fiel aos gatilhos, permissões e inputs reais.

## Verificação local

```powershell
dotnet restore TEC.Security.slnx
dotnet build TEC.Security.slnx -c Release
dotnet test --solution TEC.Security.slnx -c Release
$env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT = "1"; dotnet test --solution TEC.Security.slnx -c Release; Remove-Item Env:DOTNET_SYSTEM_GLOBALIZATION_INVARIANT
git diff --check
```

O CI também valida convenções, pacote e workflows reutilizáveis. Não afirme que o CI está funcional apenas com build/testes locais: confirme que as tags chamadas existem e que os `permissions` do chamador incluem o mínimo exigido pelo workflow reutilizável.