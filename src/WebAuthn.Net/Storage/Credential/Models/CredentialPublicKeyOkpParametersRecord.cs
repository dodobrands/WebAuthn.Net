using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;

namespace WebAuthn.Net.Storage.Credential.Models;

/// <summary>
///     Model for storing data about a public COSE key in OKP format.
/// </summary>
public class CredentialPublicKeyOkpParametersRecord
{
    /// <summary>
    ///     Constructs <see cref="CredentialPublicKeyOkpParametersRecord" />.
    /// </summary>
    /// <param name="crv">COSE elliptic curve for a public key in OKP format.</param>
    /// <param name="x">Public Key.</param>
    public CredentialPublicKeyOkpParametersRecord(CoseOkpEllipticCurve crv, byte[] x)
    {
        Crv = crv;
        X = x;
    }

    /// <summary>
    ///     COSE elliptic curve for a public key in OKP format.
    /// </summary>
    public CoseOkpEllipticCurve Crv { get; }

    /// <summary>
    ///     Public Key.
    /// </summary>
    public byte[] X { get; }
}
