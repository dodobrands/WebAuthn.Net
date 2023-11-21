using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

/// <summary>
///     <a href="https://datatracker.ietf.org/doc/html/rfc9053#section-7">COSE Key types</a>.
/// </summary>
/// <remarks>
///     Key types are identified by the "kty" member of the COSE_Key object.
/// </remarks>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum CoseKeyType
{
    /// <summary>
    ///     Octet Key Pair
    /// </summary>
    OKP = 1,

    /// <summary>
    ///     Elliptic Curve Keys w/ x- and y-coordinate pair
    /// </summary>
    EC2 = 2,

    /// <summary>
    ///     <a href="https://www.rfc-editor.org/rfc/rfc8230.html#section-4">RSA Key</a>
    /// </summary>
    RSA = 3
}
