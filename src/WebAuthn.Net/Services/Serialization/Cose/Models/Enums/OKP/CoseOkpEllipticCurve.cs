namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;

/// <summary>
///     <a href="https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves">COSE elliptic curves</a> for public keys in OKP format.
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://www.rfc-editor.org/rfc/rfc9053.html#section-2.2">RFC9053 CBOR Object Signing and Encryption (COSE): Initial Algorithms - §2.2. Edwards-Curve Digital Signature Algorithm (EdDSA)</a>
///     </para>
///     <para>
///         In that document, the signature algorithm is instantiated using parameters for the edwards25519 and edwards448 curves
///         For use with COSE, only the pure EdDSA version is used.
///     </para>
/// </remarks>
public enum CoseOkpEllipticCurve
{
    /// <summary>
    ///     Ed25519 for use w/ EdDSA only
    /// </summary>
    Ed25519 = 6
}
