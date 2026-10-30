# ADR 0009: Tipo da Identidade por Regras do Esquema, com Recusa do Token Não Reconhecido

## Status
Aprovado

## Data
2026-10-29

## Contexto
O tipo da identidade (`Kind`: usuário ou aplicação) decide `[TecAuthorize(Kinds = ...)]`, se os escopos do token valem (só
para usuário) e chega ao `IPermissionStore`. Durante o desenvolvimento da 0.0.1, o provedor OpenID Connect o inferia por uma heurística fixa (`gty`,
`idtyp`, `preferred_username` começando com `service-account-`, `sub` igual a `azp`/`client_id`), e qualquer outro caso
virava `User`. Isso tinha dois problemas:
1. **Aplicação passando como pessoa**: um token de aplicação sem esses marcadores, como o app-only do Entra ID sem o claim
   opcional `idtyp`, chegava como `User` e passava em endpoints com `Kinds = User`.
2. **Claim editável decidindo o tipo**: o `preferred_username` é editável no IdP, pelo usuário ou pelo administrador do
   tenant. Bastava trocar o username por `service-account-...` para uma pessoa virar aplicação e passar em
   `Kinds = Application`.

Não existe um sinal universal: cada IdP marca o token de aplicação de um jeito (`idtyp` no Entra ID, `gty` no Auth0, `sub`
igual ao client no Okta e no Cognito, `client_id` só nas contas de serviço do Keycloak, ausência de `scp` no Entra ID).

## Decisão
- O tipo vem de regras por esquema, em [`OpenIdConnectKindOptions`](../../TEC.Security.OpenIdConnect/OpenIdConnectOptions.cs)
  (`OpenIdConnectApiOptions.Kind`, também lidas da seção `Kind`):
  - claims que indicam aplicação, no formato `claim=valor` (padrão `idtyp=app` e `gty=client-credentials`);
  - claims que indicam usuário (padrão `idtyp=user`, `sid=*` e `auth_time=*`);
  - `sub` igual ao client (`azp`, `client_id`, `clientId`, `cid` ou `appid`) indica aplicação;
  - a regra do `scp` do Entra ID (com `scp`, pessoa; sem `scp`, ou com `scp` vazio ou `/`, aplicação), ligada sozinha quando a
    `Authority` é do Entra ID.
- Token que nenhuma regra reconhece é **recusado** (`Unresolved = Reject`). Sinais dos dois tipos no mesmo token também
  recusam. Quem conhece o IdP pode escolher `User` ou `Application` para o token sem sinal.
- Regras sobre claims editáveis (`preferred_username`, `name`, `email`, `upn`...) ou reservados (`tec_*`) são recusadas no
  registro: a aplicação não sobe com elas.
- O login web não usa as regras: o ID token de um login interativo é sempre de uma pessoa.

**Por que recusar.** Para o token sem sinal reconhecido há três saídas, e só a recusa não concede acesso indevido. Supor
`User` repete o problema 1. Supor `Application` deixa pessoas sem sinal reconhecido (os usuários do Auth0, por exemplo)
passarem em endpoints só de serviços, além de descartar os escopos delas. A recusa troca o risco de acesso por um erro
visível: 401 com o motivo no log 3201, corrigido na configuração do esquema.

## Consequências
### Positivas
- Um token de aplicação não reconhecido nunca passa como pessoa, nem o contrário: `Kinds` volta a servir para separar pessoas
  de serviços.
- Claims que o usuário controla não mudam o tipo da identidade.
- O Entra ID funciona com ou sem o claim opcional `idtyp`.

### Neutras / Negativas
- Configuração obrigatória: IdPs cujos tokens não trazem sinal reconhecido são recusados até a configuração (contas de
  serviço do Keycloak precisam de `client_id=*`; usuários do Auth0, de `Unresolved = User`). As receitas estão em
  [provedor-openid-connect.md](../provedor-openid-connect.md), mas a conferência final é com um token real decodificado.
- A regra do Entra ID é ligada pelo host da `Authority`; um proxy na frente do Entra ID exige `UseEntraIdScpRule = true`.
- Os padrões dependem de como cada IdP emite o token. Uma versão nova do IdP que mude os claims pode exigir ajuste nas regras.
