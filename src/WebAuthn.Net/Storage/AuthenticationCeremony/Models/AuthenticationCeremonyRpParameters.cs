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
    /// <param name="allowIframe">Flag determining whether iframe operation is allowed. If <see langword="true" />, then <see cref="TopOrigins" /> must be non-null.</param>
    /// <param name="topOrigins">Expected allowed top origins - parent domains of iframes within which the authentication ceremony is performed. Only matters if <see cref="AllowIframe" /> is <see langword="true" />.</param>
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
    ///     Flag determining whether iframe operation is allowed. If <see langword="true" />, then <see cref="TopOrigins" /> must be non-null.
    /// </summary>
    [MemberNotNullWhen(true, nameof(TopOrigins))]
    public bool AllowIframe { get; }

    /// <summary>
    ///     Expected allowed top origins - parent domains of iframes within which the authentication ceremony is performed. Only matters if <see cref="AllowIframe" /> is <see langword="true" />.
    /// </summary>
    public string[]? TopOrigins { get; }
}
