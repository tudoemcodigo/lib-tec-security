# ADR 0004: Tenants Vindos do Cadastro da Aplicação, com Recarga que Falha Fechada por Entrada

## Status
Aprovado (registro retroativo)

## Data
2026-10-23

## Contexto
Em sistemas multi-tenant, o tenant da aplicação (`contoso`) precisa estar ligado ao tenant do provedor (ex.: `tid`). Três riscos aparecem:
1. **Tenant vindo do token, de header ou de query**: o cliente escolheria o próprio tenant.
2. **"Aceita qualquer tenant"**: uma API multi-tenant sem lista aceita tokens de qualquer organização.
3. **Edição de configuração com erro**: se uma versão inválida do cadastro fosse recusada por inteiro, a versão anterior continuaria valendo e **manteria ativo um tenant que a mesma edição desativou**; se fosse aceita sem validar, uma entrada quebrada poderia liberar acesso.

Além disso, `ToUpperInvariant` fora do ASCII junta letras diferentes (`ſ` vira `S`), o que permitiria um id externo forjado resolver para o tenant de outro.

## Decisão
- O contrato é [`ITenantRegistry`](../../TEC.Security/Abstractions/ITenantRegistry.cs) (`FindByExternalId`, `Find`, `GetEnabledExternalIds`), Singleton, com consultas síncronas sobre dados em memória. O tenant da aplicação sai **sempre** do cadastro e vai para o claim `tec_tenant`; o id externo só serve para encontrá-lo.
- O padrão é o [`ConfigurationTenantRegistry`](../../TEC.Security/Tenants/ConfigurationTenantRegistry.cs), lido de `Security:Tenants` com recarga (`reloadOnChange`), em um *snapshot* imutável trocado por inteiro. `security.UseTenantRegistry<T>()` troca a fonte.
- Ids de tenant, tipos de provedor e ids externos têm formato estrito (só ASCII); um mesmo id externo não pode estar em dois tenants.
- Na **subida**, qualquer erro no cadastro impede a aplicação de iniciar. Na **recarga**, a versão nova vale **por entrada** (log 3101): as entradas válidas entram em uso, inclusive desativações e remoções, e só as com erro falham fechadas (id inválido ou repetido: o tenant sai; provedor ou id externo inválido: o tenant fica inativo; id externo em dois tenants: deixa de ser resolvido).
- `SecurityOptions.RequireTenant` exige tenant cadastrado e ativo; tenant inativo ou inexistente resulta em 401 `SEGURANCA_TENANT_NAO_PERMITIDO`, indistinguível de credencial inválida para o cliente. No login web, o tenant ativo é conferido a cada requisição.

## Consequências
### Positivas
- Ativar, desativar ou remover um tenant vale na próxima requisição, sem reiniciar, inclusive para sessões abertas, mesmo que outra entrada da edição tenha erro.
- Nenhuma edição consegue manter ativo o que ela mesma revogou, nem ativar uma entrada com erro.
- O cliente não descobre quais tenants existem.

### Neutras / Negativas
- Um erro numa entrada existente a desliga até a correção (o log 3101 avisa).
- Com vários arquivos de configuração, listas JSON são mescladas por índice: mantenha o cadastro numa única fonte.
- O cadastro decide quem entra, não o que cada um vê: filtrar os dados pelo `TenantId` é responsabilidade da aplicação.
