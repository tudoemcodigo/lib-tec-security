namespace TEC.Security.Abstractions;

/// <summary>Tenant cadastrado na aplicação.</summary>
/// <param name="Id">Identificador do tenant na aplicação (ex.: <c>cliente-x</c>).</param>
/// <param name="Name">Nome de exibição.</param>
/// <param name="Enabled">Tenant ativo. Identidades de tenant inativo não autenticam.</param>
public sealed record TenantInfo(string Id, string? Name, bool Enabled);

/// <summary>
/// Cadastro de tenants da aplicação e do vínculo com os tenants dos provedores de identidade (ex.: <c>tid</c> do Entra ID →
/// <c>cliente-x</c>). Singleton.
/// </summary>
/// <remarks>
/// <para>Padrão: lido de <c>Security:Tenants</c> com recarga (<c>reloadOnChange</c>): incluir, desativar ou remover um tenant
/// no appsettings vale na próxima requisição, sem reiniciar. Na inicialização, um cadastro inválido impede a aplicação de subir.
/// Numa recarga com erro (ex.: o mesmo id externo em dois tenants), a versão nova vale <b>por entrada</b>, com log de erro
/// (evento 3101): as entradas válidas entram em uso, inclusive desativações e remoções, e as com erro falham fechadas (o id
/// externo repetido deixa de ser resolvido; tenant com id externo fora do formato fica inativo). O cadastro anterior não é
/// mantido, para que um erro em uma entrada não preserve um tenant que a mesma edição desativou.</para>
/// <para>Para guardar o cadastro no banco, implemente esta interface e registre com <c>security.UseTenantRegistry&lt;T&gt;()</c>.
/// As consultas são síncronas e chamadas a cada autenticação: mantenha o cadastro em memória.</para>
/// </remarks>
public interface ITenantRegistry
{
    /// <summary>Tenant da aplicação vinculado ao tenant <paramref name="externalTenantId"/> do provedor <paramref name="provider"/>.</summary>
    TenantInfo? FindByExternalId(string provider, string externalTenantId);

    /// <summary>Tenant pelo id da aplicação.</summary>
    TenantInfo? Find(string tenantId);

    /// <summary>Ids externos de tenants <b>ativos</b> do provedor (ex.: lista de <c>tid</c> aceitos por uma API Entra multi-tenant).</summary>
    IReadOnlySet<string> GetEnabledExternalIds(string provider);
}

/// <summary>Tenant da operação atual (Scoped), resolvido a partir da identidade autenticada, nunca de header ou query.</summary>
public interface ICurrentTenant
{
    /// <summary>Id do tenant, ou <c>null</c> sem tenant.</summary>
    string? Id { get; }

    /// <summary>Dados do tenant no cadastro (ou <c>null</c>).</summary>
    TenantInfo? Info { get; }
}
