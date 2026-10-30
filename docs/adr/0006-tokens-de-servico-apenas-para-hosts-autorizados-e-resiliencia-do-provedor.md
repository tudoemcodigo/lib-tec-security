# ADR 0006: Tokens de Serviço Só para Hosts Autorizados, com Resiliência do Provedor de Token

## Status
Aprovado (registro retroativo)

## Data
2026-10-23

## Contexto
Um serviço que chama outro com o token da própria aplicação (client credentials) enfrenta dois riscos opostos:
1. **Exfiltração do token**: se a URL de destino vier de dado externo (redirecionamento, configuração adulterada, SSRF), o token dá acesso ao serviço de destino em nome da aplicação e iria parar em outro host ou em outra porta do mesmo host.
2. **Cascata de falhas**: quando o provedor de identidade fica lento ou cai, cada requisição de saída esperaria o tempo limite inteiro, serializada pela obtenção do token, e derrubaria os serviços chamadores.
Um token curto (ex.: 5 minutos, padrão do Keycloak) também não pode ser descartado do cache a cada chamada.

## Decisão
- O contrato é [`IAccessTokenProvider`](../../TEC.Security/Abstractions/IAccessTokenProvider.cs); o [`AccessTokenHandler`](../../TEC.Security/Tokens/AccessTokenHandler.cs) (`DelegatingHandler`) anexa `Authorization: Bearer` **somente** quando o destino está em `AllowedHosts` (comparação exata do host IDN, sem diferenciar maiúsculas), usa HTTPS (ou HTTP em loopback com `AllowHttpForLoopback`) e não traz usuário na URL. Entradas sem porta exigem a porta padrão do protocolo; `host:porta` exige aquela porta. Destino fora da regra é **bloqueado** com `HttpRequestException` (log 3121). Um `Authorization` já presente é mantido.
- A base [`CachingAccessTokenProvider`](../../TEC.Security/Tokens/CachingAccessTokenProvider.cs) para provedores próprios: cache por conjunto de escopos (máximo de 1024), uma obtenção por conjunto ao mesmo tempo, renovação antes da expiração (`min(5 minutos, 1/4 da validade)`), e, se a renovação falhar, o token atual continua em uso enquanto valer mais de 30 segundos (log 3122). Tempo limite sem cancelamento do chamador é falha do provedor.
- O [`SecurityCircuitBreaker`](../../TEC.Security/Resilience/SecurityCircuitBreaker.cs), sobre `Polly.Core`, abre depois de falhas repetidas (`SecurityCircuitBreakerOptions`: razão 0,5, 10 chamadas, janela e pausa de 30 s), e as chamadas seguintes falham na hora com `SecurityCircuitOpenException`. Cancelamento pedido pelo chamador não abre o circuito; na chamada de teste conta como falha.
- Falha do provedor sem token utilizável vira [`SecurityTokenAcquisitionException`](../../TEC.Security/Tokens/CachingAccessTokenProvider.cs) (`AppException`, HTTP 502, `SEGURANCA_PROVEDOR_INDISPONIVEL`), com mensagem genérica; a causa fica em `InnerException`. Métricas e traces não levam o token ([`SecurityDiagnostics`](../../TEC.Security/Diagnostics/SecurityDiagnostics.cs)).
- O provedor de client credentials do OpenID Connect ([`OpenIdConnectAccessTokenProvider`](../../TEC.Security.OpenIdConnect/OpenIdConnectAccessTokenProvider.cs)) herda o `CachingAccessTokenProvider`: mesmo circuit breaker, mesma margem de renovação, mesmo fallback para o token atual e mesmo limite de conjuntos de escopos.

## Consequências
### Positivas
- O token de serviço não chega a host, porta ou protocolo não autorizados, mesmo com URL adulterada.
- Uma instabilidade passageira do IdP não derruba as chamadas enquanto houver token válido; uma queda prolongada falha rápido, sem acumular esperas.
- Tokens curtos são reaproveitados.

### Neutras / Negativas
- O circuito aberto e o fallback do token atual valem para todo provedor que herda o `CachingAccessTokenProvider`, inclusive o OpenID Connect; com o circuito aberto e sem token utilizável, o chamador recebe `SecurityTokenAcquisitionException` com `SecurityCircuitOpenException` em `InnerException`.
- A resposta de sucesso do endpoint de token do provedor OpenID Connect não tem teto de tamanho, e o `HttpClient` do provedor vive no Singleton, fora da rotação de handlers do `IHttpClientFactory`.
- Todo `AllowedHosts` precisa ser mantido mínimo e sem hosts controlados por terceiros; erro de configuração derruba a chamada com `HttpRequestException`, não envia o token.
- O `AddOpenIdConnectAccessToken` cria o handler sem logger, então o evento 3121 não é registrado por esse caminho.

## Atualização (2026-10-29)
Duas consequências acima deixaram de valer. A resposta do endpoint de token agora tem teto de 256 KB (`OpenIdConnectAccessTokenProvider.MaxResponseBytes`): acima disso, pelo `Content-Length` ou durante a leitura, a obtenção falha. E o `AddOpenIdConnectAccessToken` passou a criar o handler com o `ILogger<AccessTokenHandler>` do container, então o evento 3121 é registrado também por esse caminho. A decisão em si não mudou.
