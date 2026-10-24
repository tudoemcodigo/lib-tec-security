# ADR 0007: Identidade de Sistema e `RunAs` para Workers, Jobs e Mensageria

## Status
Aprovado (registro retroativo)

## Data
2026-10-23

## Contexto
Fora de uma requisição HTTP (jobs, consumidores de fila, `BackgroundService`) não há `HttpContext.User`, mas o código de negócio, a auditoria do TEC.ORM e o TEC.Cqrs continuam precisando saber **quem** executa. As alternativas simples têm problemas:
1. **Aceitar qualquer `ClaimsPrincipal`** montado à mão permitiria forjar um usuário privilegiado.
2. **Estado estático** vazaria a identidade entre hosts no mesmo processo (testes paralelos, hosts lado a lado).
3. **Identidade presa ao escopo de DI** não acompanharia as trocas de identidade de um worker que processa mensagens de usuários diferentes, nem fluxos paralelos no mesmo escopo.
4. **Token em mensagens de fila** expira e vaza dados sensíveis.

## Decisão
- O contrato é [`ISecurityContext`](../../TEC.Security/Abstractions/ISecurityContext.cs), Singleton: `CreateSystemPrincipalAsync(serviceName, tenantId?, roles?)` cria uma identidade `PrincipalKind.System` (`system:{nome}`, minúsculas, dígitos e hífen, 3 a 40) passando pelo mesmo `SecurityIdentityFactory` (tenant ativo do cadastro, papéis convertidos em permissões), e `RunAs(principal)` define a identidade do fluxo assíncrono atual até o `IDisposable` ser descartado, com escopos aninhados.
- `System` só nasce dentro do processo: os provedores criam apenas `User` ou `Application`, e os claims `tec_*` de tokens são descartados ([ADR 0001](0001-identidade-normalizada-com-securityuser-e-externalidentity.md)). `RunAs` recusa (`InvalidOperationException`) um principal que não foi normalizado pelo TEC.Security.
- O estado é um `AsyncLocal` **por instância** do [`SecurityContext`](../../TEC.Security/Context/SecurityContext.cs); ao descartar o escopo, o *holder* é limpo, de modo que tarefas filhas que continuam depois dele deixam de ver a identidade.
- O `ISecurityUser` lê o principal a cada acesso pela `IPrincipalSource` ([`CurrentSecurityUser`](../../TEC.Security/Context/CurrentSecurityUser.cs)), com o par (principal, usuário) numa única referência imutável; no ASP.NET Core a fonte ([`HttpPrincipalSource`](../../TEC.Security.AspNetCore/HttpPrincipalSource.cs)) dá precedência ao `RunAs` sobre o `HttpContext.User`.
- Para mensagens "em nome" de um usuário, transporta-se id e tenant (nunca o token) e executa-se como sistema, com o usuário original como dado de auditoria.

## Consequências
### Positivas
- Workers e filas têm identidade e tenant auditáveis, sem ASP.NET Core (o pacote `TEC.Security` basta).
- Nenhum token externo consegue produzir uma identidade de sistema.
- Hosts no mesmo processo e fluxos paralelos no mesmo escopo não misturam identidades.

### Neutras / Negativas
- Quem processa mensagens precisa criar a identidade de sistema explicitamente; a autorização por usuário deve ser validada no produtor, que tinha o token.
- Dentro de uma API com worker no mesmo processo, o `IPrincipalAccessor` do TEC.Cqrs precisa ser trocado por um que leia o `ISecurityUser` ([workers.md](../workers.md#teccqrs-fora-do-http)).
- A identidade de sistema deve receber só os papéis de que o job precisa.
