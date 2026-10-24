<div align="center">
<img src="https://www.tudoemcodigo.com/marca/PNG/tudoemcodigo-icone-512.png" alt="Tudo em Código" width="90" />
</div>

# 🏛️ Registros de Decisões de Arquitetura (ADR) — TEC.Security

Este diretório contém os Registros de Decisões de Arquitetura (**Architecture Decision Records — ADRs**) do componente **TEC.Security**.

O objetivo destes registros é documentar de forma clara, contextualizada e justificada as escolhas técnicas, de engenharia de software e de segurança adotadas na biblioteca, orientando a manutenção, evolução e auditoria contínua da plataforma. Os registros abaixo são **retroativos**: descrevem decisões já presentes no código da versão `0.0.1`, conferidas nele e na [revisão técnica](../revisao-tecnica.md).

---

## 📑 Índice de Decisões

| ADR | Título | Status | Data | Contexto Resumido |
|:---:|:---|:---:|:---:|:---|
| [0001](0001-identidade-normalizada-com-securityuser-e-externalidentity.md) | **Identidade Normalizada com `ISecurityUser`, `ExternalIdentity` e Claims `tec_*`** | Aprovado | 2026-10-23 | Todo provedor vira o mesmo `ClaimsPrincipal` normalizado; claims `tec_*` vindos do provedor são descartados e a identidade sem a marca é anônima. |
| [0002](0002-autorizacao-fechada-por-padrao-e-controles-conferidos-na-subida.md) | **Autorização Fechada por Padrão e Controles Obrigatórios Conferidos na Subida** | Aprovado | 2026-10-23 | `FallbackPolicy` exigindo identidade normalizada, `[TecAuthorize]` único e validação de JWT, OIDC, cookie e endpoints depois de toda configuração: configuração insegura impede a subida. |
| [0003](0003-permissoes-da-aplicacao-a-partir-de-papeis-com-ipermissionstore.md) | **Permissões da Aplicação a Partir de Papéis com `IPermissionStore` e Cache de Consulta Única** | Aprovado | 2026-10-23 | Papéis do token convertidos em permissões por appsettings ou fonte própria, com cache limitado, uma consulta por identidade e falha fechada. |
| [0004](0004-tenants-do-cadastro-da-aplicacao-com-recarga-por-entrada.md) | **Tenants Vindos do Cadastro da Aplicação, com Recarga que Falha Fechada por Entrada** | Aprovado | 2026-10-23 | O tenant nunca vem do token; o cadastro recarrega sem reinício e uma edição com erro não mantém ativo o que ela mesma revogou. |
| [0005](0005-api-keys-guardadas-como-hash-com-validade-obrigatoria.md) | **API Keys de 256 Bits Guardadas Só como Hash, com Validade Obrigatória** | Aprovado | 2026-10-23 | Chaves `tec_{id}_{segredo}` com SHA-256 em tempo constante, formato canônico, `ExpiresOn` obrigatório e recarga por chave. |
| [0006](0006-tokens-de-servico-apenas-para-hosts-autorizados-e-resiliencia-do-provedor.md) | **Tokens de Serviço Só para Hosts Autorizados, com Resiliência do Provedor de Token** | Aprovado | 2026-10-23 | `AccessTokenHandler` com `AllowedHosts`, HTTPS e portas estritas; cache, renovação antecipada e circuit breaker (`Polly.Core`) para o provedor de token. |
| [0007](0007-identidade-de-sistema-e-runas-para-workers.md) | **Identidade de Sistema e `RunAs` para Workers, Jobs e Mensageria** | Aprovado | 2026-10-23 | `PrincipalKind.System` só criado no processo, `RunAs` sobre `AsyncLocal` por instância e recusa de principais não normalizados. |
| [0008](0008-provedor-plugavel-e-openid-connect-agnostico.md) | **Provedor de Identidade Plugável e Provedor OpenID Connect Agnóstico** | Aprovado | 2026-10-23 | Pacotes em camadas, `JwtProviderDefinition`/`WebLoginDefinition` como extensão, seletor de esquema `TEC` e um provedor OpenID Connect para Keycloak, Auth0, Okta, Entra ID e outros. |

---
[🏠 README](../../README.md) · [📚 Documentação](../README.md)
