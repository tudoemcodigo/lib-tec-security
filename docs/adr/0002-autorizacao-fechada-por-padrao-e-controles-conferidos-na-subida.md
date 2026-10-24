# ADR 0002: Autorização Fechada por Padrão e Controles Obrigatórios Conferidos na Subida

## Status
Aprovado (registro retroativo)

## Data
2026-10-23

## Contexto
Os incidentes mais comuns de autenticação em APIs .NET vêm de configuração, não de criptografia:
1. **Endpoint esquecido** sem `[Authorize]` fica público.
2. **Validação desligada "para funcionar"**: alguém desliga `ValidateAudience` ou aceita `alg: none`, localmente ou num `PostConfigure` de outra biblioteca.
3. **`[AllowAnonymous]` anulando a regra**: um `[AllowAnonymous]` no controller anula em silêncio o atributo da action.
4. **Credencial desconhecida tratada como anônima**: um header `Authorization` de outro tipo, ou um token de emissor não registrado, seguiria como requisição anônima.
5. **Troca tardia de peças** (`Events`, `IAuthorizationPolicyProvider`, `FallbackPolicy`) que desfaz a normalização ou a regra.

## Decisão
O `AddAspNetCore()` ([`SecurityBuilderAspNetCoreExtensions`](../../TEC.Security.AspNetCore/SecurityBuilderAspNetCoreExtensions.cs)) fecha o sistema e confere os controles **depois de toda configuração**:
- `DefaultPolicy` e `FallbackPolicy` exigem a [`TecAuthenticatedRequirement`](../../TEC.Security.AspNetCore/Authorization/TecRequirement.cs): identidade autenticada **e** normalizada. Só `[AllowAnonymous]` abre um endpoint.
- Um único atributo, [`[TecAuthorize]`](../../TEC.Security.AspNetCore/Authorization/TecAuthorizeAttribute.cs) (e `RequireTecAuthorization`), com permissões, papéis, escopos, tipos e esquemas. A regra viaja como nome de policy codificado (`TEC|p=...|k=...`), resolvido pelo [`TecAuthorizationPolicyProvider`](../../TEC.Security.AspNetCore/Authorization/TecAuthorizationPolicyProvider.cs); assim vale em controllers, Minimal APIs, gRPC, hubs SignalR e Blazor. A negação usa `context.Fail`.
- O [`JwtHardening`](../../TEC.Security.AspNetCore/Authentication/JwtHardening.cs) aplica padrões endurecidos e o [`SecurityOptionsValidators`](../../TEC.Security.AspNetCore/Authentication/SecurityOptionsValidators.cs) confere por `IValidateOptions` os controles obrigatórios: validação de emissor, audiência, validade e assinatura; algoritmos só RS\*/PS\*/ES\*; ganchos que trocariam chaves ou a leitura do token; `Events` não substituídos; cookie e OIDC do login web; `FallbackPolicy`/`DefaultPolicy`. O `SecuritySchemesStartupValidator` (no mesmo arquivo) materializa as opções na subida.
- O [`EndpointSecurityValidator`](../../TEC.Security.AspNetCore/Authorization/EndpointSecurityValidator.cs) recusa `[TecAuthorize]` vazio, fora do formato ou junto de `[AllowAnonymous]`.
- O esquema [`TEC.None`](../../TEC.Security.AspNetCore/Authentication/NoCredentialsHandler.cs) faz a autenticação **falhar** para credencial não reconhecida.
- As respostas 401/403 usam o `ApiResponse` do TEC.Core, genéricas e idênticas para todo motivo ([`TecAuthorizationResultHandler`](../../TEC.Security.AspNetCore/Authorization/TecAuthorizationResultHandler.cs)); o motivo vai para o log de auditoria (evento 3203) e as métricas.

## Consequências
### Positivas
- Configuração insegura derruba a **subida**, não a primeira requisição nem a produção.
- Um endpoint novo nasce protegido; o desenvolvedor precisa abrir explicitamente.
- A regra de autorização é lida pelo `IAuthorizeData`, então não depende de middleware específico.

### Neutras / Negativas
- Não é possível desligar um controle "só neste ambiente": as exceções são explícitas e pontuais (`IncludeErrorDetails` e `ApiKeyRequiresHttps` em Development, `AllowHttpForLoopback`).
- Um `IAuthorizationPolicyProvider` próprio da aplicação é recusado; a aplicação usa policies nomeadas ou `[TecAuthorize]`.
- O componente não faz rate limiting: ele é responsabilidade da aplicação ou do gateway ([seguranca.md](../seguranca.md#rate-limiting)).
