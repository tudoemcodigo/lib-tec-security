# ADR 0003: Permissões da Aplicação a Partir de Papéis com `IPermissionStore` e Cache de Consulta Única

## Status
Aprovado (registro retroativo)

## Data
2026-10-23

## Contexto
O provedor informa **papéis** (ex.: o app role `Gerente`); a aplicação decide por **permissões** (`pedidos:cancelar`). A conversão precisa:
1. Ficar sob controle da aplicação, e não do IdP ou do administrador de cada tenant cliente.
2. Poder vir do `appsettings` (recarregável) ou de um banco, sem acoplar o núcleo a nenhum deles.
3. Não esgotar a fonte nem a memória: a consulta acontece a cada autenticação, e tokens com muitos papéis ou muitas identidades distintas são um vetor de abuso.
4. Falhar fechada: uma fonte indisponível nunca pode autorizar sem permissões conhecidas.

## Decisão
- O contrato é [`IPermissionStore`](../../TEC.Security/Abstractions/IPermissionStore.cs), consultado uma vez por autenticação com um `PermissionContext` (provedor, esquema, id, tenant, tipo e papéis). O resultado vira claims `tec_perm`.
- O padrão é o [`ConfigurationPermissionStore`](../../TEC.Security/Permissions/ConfigurationPermissionStore.cs): `Security:Permissions:Roles` (todos os tenants) mais `Security:Permissions:Tenants:{tenant}:Roles` (somente aquele tenant), com recarga.
- Fonte própria: `security.UsePermissionStore<T>(cacheDuration)` ([`SecurityBuilder`](../../TEC.Security/DependencyInjection/SecurityBuilder.cs)), registrada como Singleton e envolvida por um [`CachingPermissionStore`](../../TEC.Security/Permissions/CachingPermissionStore.cs): `IMemoryCache` privado com limite de 50.000 entradas, chave de tamanho fixo (SHA-256 de provedor, esquema, tenant, id, tipo e papéis em ordem), **uma consulta por chave** (`SingleFlight` do TEC.Core, sem *cache stampede*), duração padrão de 5 minutos (0 desliga; máximo de 1 hora). Exceções e resultados acima de 512 itens não vão para o cache.
- `SecurityOptions.RolesAsPermissions` (`bool?`) soma os próprios papéis às permissões. Quando não definido, o `SecurityIdentityFactory` usa `true`, ou `false` para identidades de um provedor multi-tenant (`ExternalIdentity.MultiTenant`). O indicador fica na identidade normalizada (claim `tec_multi_tenant`), então a revalidação da sessão aplica o mesmo padrão do login.
- Falha fechada: a exceção do store faz a autenticação falhar (`SEGURANCA_PROVEDOR_INDISPONIVEL`, log 3003), e o tempo limite do store (cancelamento sem pedido do chamador) é tratado como falha do provedor.

## Consequências
### Positivas
- A decisão de acesso depende de permissões da aplicação, não de nomes de papéis do IdP.
- A fonte é trocável (banco, serviço) sem tocar no resto; o cache evita uma consulta por requisição e protege a fonte sob carga.
- Permissões por tenant permitem separar o que o administrador de um tenant cliente pode conceder.

### Neutras / Negativas
- Uma permissão revogada na fonte vale até o fim do cache (padrão 5 minutos); para revogação imediata, reduza ou desligue o cache.
- Com `RolesAsPermissions` não definido, o papel do token também vale como permissão, exceto com um provedor multi-tenant, em que o padrão é `false`; `true` explícito com identidade multi-tenant gera o aviso 3403 (uma vez por processo). Em APIs multi-tenant, use permissões por tenant ([tenants.md](../tenants.md#️-segurança)).
- O store é Singleton: dependências Scoped (ex.: `DbContext`) vêm de um `IServiceScopeFactory`.
