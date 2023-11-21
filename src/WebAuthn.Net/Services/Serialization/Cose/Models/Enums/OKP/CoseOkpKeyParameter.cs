using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;

/// <summary>
///     Valid parameters for a key encoded in OKP format.
/// </summary>
/// <remarks>
///     <a href="https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters">IANA COSE Key Type Parameters registry</a>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum CoseOkpKeyParameter
{
    /// <summary>
    ///     EC identifier - Taken from the "COSE Elliptic Curves" registry
    /// </summary>
    crv = -1,

    /// <summary>
    ///     Public Key
    /// </summary>
    x = -2
}
