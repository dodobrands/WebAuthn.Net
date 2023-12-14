using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Storage.Credential.Models;

/// <summary>
///     Model for storing data about a public COSE key in EC2 format.
/// </summary>
public class CredentialPublicKeyEc2ParametersRecord
{
    /// <summary>
    ///     Constructs <see cref="CredentialPublicKeyEc2ParametersRecord" />.
    /// </summary>
    /// <param name="crv">COSE elliptic curve for a public key in EC2 format.</param>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    public CredentialPublicKeyEc2ParametersRecord(CoseEc2EllipticCurve crv, byte[] x, byte[] y)
    {
        Crv = crv;
        X = x;
        Y = y;
    }

    /// <summary>
    ///     COSE elliptic curve for a public key in EC2 format.
    /// </summary>
    public CoseEc2EllipticCurve Crv { get; }

    /// <summary>
    ///     X coordinate.
    /// </summary>
    public byte[] X { get; }

    /// <summary>
    ///     Y coordinate.
    /// </summary>
    public byte[] Y { get; }
}
