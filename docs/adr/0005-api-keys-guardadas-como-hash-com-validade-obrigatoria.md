# ADR 0005: API Keys de 256 Bits Guardadas Só como Hash, com Validade Obrigatória

## Status
Aprovado (registro retroativo)

## Data
2026-10-23

## Contexto
Integrações que não falam OAuth (ERP, scripts, parceiros) precisam de uma credencial simples. Os problemas clássicos de API keys:
1. **Chave guardada em claro** na configuração, no repositório ou no banco.
2. **Comparação que vaza o tempo**, revelando quais ids existem ou o quanto da chave está certo.
3. **Chave eterna** e impossível de rotacionar sem derrubar o cliente.
4. **Variações aceitas** da mesma chave (Base64 não canônico) e entradas enormes que consomem CPU.
5. **Recarga de configuração com erro** que deixa uma chave revogada ativa, ou que gera uma exceção por requisição (amplificação de DoS).

## Decisão
- A chave tem o formato `tec_{id}_{segredo}`: id público (minúsculas, dígitos e hífen, 3 a 40) e 32 bytes aleatórios em Base64Url canônico ([`ApiKeyGenerator`](../../TEC.Security/ApiKeys/ApiKeyGenerator.cs)). O prefixo `tec_` permite *secret scanning*. Só o **SHA-256 do segredo** vai para `Security:ApiKeys:Keys:{id}:Hash`; por ter 256 bits de entropia, um hash rápido basta.
- O [`ApiKeyValidator`](../../TEC.Security/ApiKeys/ApiKeyValidator.cs) calcula sempre o hash e o compara em tempo constante (`FixedTimeEquals`), inclusive para id desconhecido (hash fictício), e zera os buffers com o segredo. Formato estrito e canônico; entradas acima de 128 caracteres nem são processadas.
- `ExpiresOn` é **obrigatório**; chave desativada, expirada ou sem validade é recusada. Rotacionar é gerar outra chave com outro id e manter as duas ativas durante a troca.
- A identidade resultante é `Application` (`apikey:{id}`), com tenant, papéis e permissões do cadastro; o tenant da chave precisa existir e estar ativo.
- Transporte: só no header configurado (padrão `X-Api-Key`, nunca `Authorization`), um único header, e só por HTTPS fora de Development ([`ApiKeyAuthenticationHandler`](../../TEC.Security.AspNetCore/Authentication/ApiKeyAuthenticationHandler.cs)). Nunca na query string.
- Uma recarga com erro vale **por chave**: as válidas da versão nova entram em uso (inclusive revogações) e as com erro ficam recusadas; a releitura de uma configuração inválida acontece no máximo uma vez por segundo. Recusas repetidas (mesmo id e motivo) geram no máximo um log 3110 por minuto, com a contagem das omitidas.

## Consequências
### Positivas
- Um vazamento da configuração não revela chaves utilizáveis.
- O tempo de resposta não revela quais ids existem.
- Revogar (`Enabled: false` ou remover a entrada) vale na próxima requisição, mesmo com outra entrada quebrada na edição.

### Neutras / Negativas
- A chave não pode ser recuperada: perdida, só gerando outra.
- O componente não limita tentativas: use `RateLimiter` ou o gateway.
- Logs de acesso de proxies e APM costumam registrar headers; mascare o header da chave em toda a cadeia.
