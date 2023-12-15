using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Models;

/// <summary>
///     Expected relying party parameters for the registration ceremony. Used to complete the registration ceremony.
/// </summary>
public class RegistrationCeremonyRpParameters
{
    /// <summary>
    ///     Constructs <see cref="RegistrationCeremonyRpParameters" />.
    /// </summary>
    /// <param name="rpId">Expected rpId when completing the registration ceremony.</param>
    /// <param name="origins">Expected origins when completing the registration ceremony.</param>
    /// <param name="allowIframe">Flag determining whether iframe operation is allowed. If <see langword="true" />, then <see cref="TopOrigins" /> must be non-null.</param>
    /// <param name="topOrigins">Expected allowed top origins - parent domains of iframes within which the authentication ceremony is performed. Only matters if <see cref="AllowIframe" /> is <see langword="true" />.</param>
    public RegistrationCeremonyRpParameters(string rpId, string[] origins, bool allowIframe, string[]? topOrigins)
    {
        RpId = rpId;
        Origins = origins;
        AllowIframe = allowIframe;
        TopOrigins = topOrigins;
    }

    /// <summary>
    ///     Expected rpId when completing the registration ceremony.
    /// </summary>
    public string RpId { get; }

    /// <summary>
    ///     Expected origins when completing the registration ceremony.
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
