using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Models;

/// <summary>
///     Expected relying party parameters for the authentication ceremony. Used to complete the authentication ceremony.
/// </summary>
public class AuthenticationCeremonyRpParameters
{
    /// <summary>
    ///     Constructs <see cref="AuthenticationCeremonyRpParameters" />.
    /// </summary>
    /// <param name="rpId">Expected rpId when completing the authentication ceremony.</param>
    /// <param name="origins">Expected origins when completing the authentication ceremony.</param>
    /// <param name="allowIframe">
    ///     Flag determining whether the Relying Party expects the authentication ceremony to run in an iframe that is not same-origin with its ancestors, within one of the <see cref="TopOrigins" />. If <see langword="true" />, then
    ///     <see cref="TopOrigins" /> must be non-null. If <see langword="false" />, such an iframe is accepted only when the client reports a <c>topOrigin</c> that is equal to <c>origin</c>.
    /// </param>
    /// <param name="topOrigins">Expected top origins - the origins of the top-level pages within which the authentication ceremony is performed in an iframe. Only matters if <see cref="AllowIframe" /> is <see langword="true" />.</param>
    public AuthenticationCeremonyRpParameters(string rpId, string[] origins, bool allowIframe, string[]? topOrigins)
    {
        RpId = rpId;
        Origins = origins;
        AllowIframe = allowIframe;
        TopOrigins = topOrigins;
    }

    /// <summary>
    ///     Expected rpId when completing the authentication ceremony.
    /// </summary>
    public string RpId { get; }

    /// <summary>
    ///     Expected origins when completing the authentication ceremony.
    /// </summary>
    public string[] Origins { get; }

    /// <summary>
    ///     Flag determining whether the Relying Party expects the authentication ceremony to run in an iframe that is not same-origin with its ancestors, within one of the <see cref="TopOrigins" />. If <see langword="true" />, then
    ///     <see cref="TopOrigins" /> must be non-null. If <see langword="false" />, such an iframe is accepted only when the client reports a <c>topOrigin</c> that is equal to <c>origin</c>.
    /// </summary>
    [MemberNotNullWhen(true, nameof(TopOrigins))]
    public bool AllowIframe { get; }

    /// <summary>
    ///     Expected top origins - the origins of the top-level pages within which the authentication ceremony is performed in an iframe. Only matters if <see cref="AllowIframe" /> is <see langword="true" />.
    /// </summary>
    public string[]? TopOrigins { get; }
}
