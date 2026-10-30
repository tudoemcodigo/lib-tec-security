using System.Security.Claims;

namespace TEC.Security.Claims;

/// <summary>
/// Identidade normalizada pelo TEC.Security. Só o <see cref="SecurityIdentityFactory"/> cria instâncias (tipo interno e
/// selado): é o tipo, e não um claim, que prova a normalização. Um principal montado à mão, por um delegate de evento ou por
/// outro esquema de autenticação, mesmo com todos os claims <c>tec_*</c>, continua anônimo para o <see cref="SecurityUser"/>.
/// </summary>
/// <remarks>
/// <para>Os claims com o prefixo reservado (<see cref="TecClaimTypes.Prefix"/>) ficam travados depois da criação: incluir ou
/// remover um deles lança <see cref="InvalidOperationException"/> (<see cref="TryRemoveClaim"/> devolve <c>false</c>). Claims
/// de outros tipos continuam livres (ex.: um <c>IClaimsTransformation</c> da aplicação).</para>
/// <para><see cref="Clone"/> preserva o tipo. A serialização não preserva (o <c>TicketSerializer</c> do cookie recria um
/// <see cref="ClaimsIdentity"/> comum): o login web reconstrói a identidade lida do próprio cookie com
/// <see cref="RestoreTrusted"/>.</para>
/// </remarks>
internal sealed class NormalizedIdentity : ClaimsIdentity
{
    private readonly bool _sealed;

    /// <summary>Cria a identidade com os claims já normalizados.</summary>
    internal NormalizedIdentity(IEnumerable<Claim> claims, string authenticationType)
        : base(claims, authenticationType, TecClaimTypes.Name, TecClaimTypes.Role)
    {
        _sealed = true;
    }

    private NormalizedIdentity(NormalizedIdentity other)
        : base(other)
    {
        _sealed = true;
    }

    /// <inheritdoc />
    public override ClaimsIdentity Clone() => new NormalizedIdentity(this);

    /// <inheritdoc />
    public override void AddClaim(Claim claim)
    {
        ThrowIfReserved(claim?.Type);
        base.AddClaim(claim!);
    }

    /// <inheritdoc />
    public override void AddClaims(IEnumerable<Claim?> claims)
    {
        ArgumentNullException.ThrowIfNull(claims);
        var list = claims.ToList();
        foreach (var claim in list)
            ThrowIfReserved(claim?.Type);

        base.AddClaims(list);
    }

    /// <inheritdoc />
    public override void RemoveClaim(Claim? claim)
    {
        ThrowIfReserved(claim?.Type);
        base.RemoveClaim(claim);
    }

    /// <inheritdoc />
    public override bool TryRemoveClaim(Claim? claim) =>
        !(_sealed && claim is not null && TecClaimTypes.IsReserved(claim.Type)) && base.TryRemoveClaim(claim);

    /// <summary>
    /// Reconstrói a identidade normalizada de um principal lido de um armazenamento confiável da própria aplicação: o cookie de
    /// sessão do login web, cifrado e autenticado pelo Data Protection e gravado só com identidade normalizada (o
    /// <c>TEC.Security.AspNetCore</c> recusa gravar outra coisa no evento <c>SigningIn</c>).
    /// </summary>
    /// <remarks>Uso exclusivo do login web do <c>TEC.Security.AspNetCore</c>. Nunca use com um principal de outra origem: a marca
    /// <see cref="TecClaimTypes.Normalized"/> sozinha não prova nada.</remarks>
    /// <returns>O principal com a identidade normalizada, ou <c>null</c> se ele não tiver a marca.</returns>
    internal static ClaimsPrincipal? RestoreTrusted(ClaimsPrincipal? principal)
    {
        if (principal is null)
            return null;

        // Mesmo objeto (ex.: ticket guardado em memória por um ITicketStore): nada a reconstruir
        if (SecurityUser.FindNormalizedIdentity(principal) is not null)
            return principal;

        foreach (var identity in principal.Identities)
        {
            if (identity.IsAuthenticated && identity.HasClaim(TecClaimTypes.Normalized, TecClaimTypes.NormalizedValue))
                return new ClaimsPrincipal(new NormalizedIdentity(identity.Claims, identity.AuthenticationType!));
        }

        return null;
    }

    private void ThrowIfReserved(string? claimType)
    {
        if (_sealed && claimType is not null && TecClaimTypes.IsReserved(claimType))
            throw new InvalidOperationException("Os claims tec_* da identidade normalizada não podem ser alterados depois da criação.");
    }
}
