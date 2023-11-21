using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

/// <summary>
///     Valid parameters for a key encoded in EC2 format.
/// </summary>
/// <remarks>
///     <a href="https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters">IANA COSE Key Type Parameters registry</a>
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum CoseEc2KeyParameter
{
    /// <summary>
    ///     EC identifier - Taken from the "COSE Elliptic Curves" registry
    /// </summary>
    crv = -1,

    /// <summary>
    ///     x-coordinate
    /// </summary>
    x = -2,

    /// <summary>
    ///     y-coordinate
    /// </summary>
    y = -3
}
