# ADR 0001: Identidade Normalizada com `ISecurityUser`, `ExternalIdentity` e Claims `tec_*`

## Status
Aprovado (registro retroativo; revisado em 2026-10-29: a normalização passou a ser provada pelo tipo da identidade, não pela marca)

## Data
2026-10-23

## Contexto
Cada provedor de identidade descreve o usuário de um jeito: `roles`, `scp`, `realm_access`, `tid`, `azp`. Uma aplicação que lê esses claims diretamente fica acoplada ao provedor e, pior, passa a confiar em dados que dependem da configuração do IdP e do administrador de cada tenant:
1. **Acoplamento**: trocar ou somar um provedor exige mexer no código de negócio.
2. **Injeção de permissões**: um atributo de usuário mapeado por engano para um claim como `permissions` ou `tenant` viraria acesso sem passar pela aplicação.
3. **Identidades "meio autenticadas"**: um `ClaimsPrincipal` criado por outro mecanismo (ou por código de terceiros) não pode ser tratado como identidade confiável.
4. **Componentes que só precisam de "quem"** (auditoria, filas) não devem depender do ASP.NET Core nem do provedor.

## Decisão
Todo provedor converte o token (ou a API key) **já validado** em um [`ExternalIdentity`](../../TEC.Security/Claims/ExternalIdentity.cs), formato neutro, e o [`SecurityIdentityFactory`](../../TEC.Security/Claims/SecurityIdentityFactory.cs) cria o `ClaimsPrincipal` normalizado:
- Claims próprios com o prefixo reservado `tec_` ([`TecClaimTypes`](../../TEC.Security/Claims/TecClaimTypes.cs)): `tec_uid`, `tec_kind`, `tec_tenant`, `tec_ext_tenant`, `tec_scheme`, `tec_provider`, `tec_name`, `tec_role`, `tec_scope`, `tec_perm`, `tec_client`, `tec_multi_tenant` e a marca `tec_normalized`.
- Todo claim `tec_*` que chega do provedor é **descartado** antes da normalização.
- A prova da normalização é o **tipo**: a fábrica cria uma identidade interna e selada ([`NormalizedIdentity`](../../TEC.Security/Claims/NormalizedIdentity.cs)) que código de fora não instancia. Um `ClaimsPrincipal` montado à mão, por um delegate de evento ou por outro esquema, mesmo com todos os claims `tec_*` e a marca, não vale. Depois de criada, os claims `tec_*` dela não podem ser incluídos nem removidos. A marca `tec_normalized` só ajuda o login web a reconhecer a identidade no próprio cookie (cifrado e autenticado pelo Data Protection, gravado só com identidade normalizada), de onde ela é reconstruída.
- A aplicação lê [`ISecurityUser`](../../TEC.Security/Abstractions/ISecurityUser.cs), que herda o `ICurrentUser` do TEC.Core e é implementado por [`SecurityUser`](../../TEC.Security/Claims/SecurityUser.cs) a partir dos claims normalizados. Sem a identidade criada pela fábrica (ou sem id, ou com tipo inválido), a identidade é **anônima**.
- O tenant e as permissões vêm da aplicação ([ADR 0003](0003-permissoes-da-aplicacao-a-partir-de-papeis-com-ipermissionstore.md) e [ADR 0004](0004-tenants-do-cadastro-da-aplicacao-com-recarga-por-entrada.md)), nunca copiados do token. Papéis, escopos e permissões são limitados a 512 itens e validados por [`SecurityRules`](../../TEC.Security/Common/SecurityRules.cs) (ASCII, `\z`); o nome de exibição é recusado por inteiro se tiver controle bidirecional, separador de linha ou surrogate solto.
- `ISecurityUser`, `ICurrentUser` e `ICurrentTenant` são Scoped e leem o principal atual a cada acesso ([`CurrentSecurityUser`](../../TEC.Security/Context/CurrentSecurityUser.cs)).
- A normalização falha fechada e sem exceção: devolve `Result` com os códigos de [`SecurityErrors`](../../TEC.Security/Common/SecurityErrors.cs); o motivo detalhado vai só para o log e a métrica.

## Consequências
### Positivas
- O mesmo código de negócio funciona com qualquer provedor, API key, identidade de sistema ou provedor de teste.
- Um IdP mal configurado não consegue injetar permissão, tenant nem tipo de identidade.
- Outro mecanismo de autenticação (ou código da aplicação) que entregue um principal com os claims `tec_*` recebe 403, não acesso.
- TEC.Cqrs, TEC.ORM e a auditoria dependem só do contrato `ICurrentUser` do TEC.Core.

### Neutras / Negativas
- O tipo não sobrevive à serialização: quem guardar o principal fora do processo (outro cookie, cache distribuído) lê de volta uma identidade anônima. O login web reconstrói a sua com um membro interno do núcleo (`InternalsVisibleTo` para o `TEC.Security.AspNetCore`), por isso os pacotes precisam estar na mesma versão.
- Os claims originais do provedor só chegam a `ISecurityUser.Principal` se o provedor os incluir em `SourceClaims` (o provedor OpenID Connect atual não inclui).
- Todo provedor novo precisa implementar a conversão para `ExternalIdentity` ([ADR 0008](0008-provedor-plugavel-e-openid-connect-agnostico.md)).
- Um membro novo em `ISecurityUser` é mudança incompatível para quem a implementa.
