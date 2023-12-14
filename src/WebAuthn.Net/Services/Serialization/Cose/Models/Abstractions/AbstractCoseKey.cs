using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;

/// <summary>
///     Abstract public key in COSE format.
/// </summary>
public abstract class AbstractCoseKey
{
    /// <summary>
    ///     The key type defined by the "kty" member of a COSE_Key object.
    /// </summary>
    public abstract CoseKeyType Kty { get; }

    /// <summary>
    ///     The identifier of the cryptographic algorithm of this public key.
    /// </summary>
    public abstract CoseAlgorithm Alg { get; }

    /// <summary>
    ///     Verifies whether the public key described by this object matches the public key in <see cref="X509Certificate2" />.
    /// </summary>
    /// <param name="certificate">A certificate containing a public key.</param>
    /// <returns><see langword="true" />, if the public keys match, otherwise - <see langword="false" />.</returns>
    public abstract bool Matches(X509Certificate2 certificate);

    /// <summary>
    ///     Verifies whether the public key described by this object matches the public key in <see cref="AsymmetricAlgorithm" />.
    /// </summary>
    /// <param name="asymmetricAlgorithm"><see cref="AsymmetricAlgorithm" /> containing a public key.</param>
    /// <returns><see langword="true" />, if the public keys match, otherwise - <see langword="false" />.</returns>
    public abstract bool Matches(AsymmetricAlgorithm asymmetricAlgorithm);

    /// <summary>
    ///     Verifies whether the public key described by this object matches the public key in another <see cref="AbstractCoseKey" />.
    /// </summary>
    /// <param name="coseKey">Another instance of <see cref="AbstractCoseKey" /> describing a public key.</param>
    /// <returns><see langword="true" />, if the public keys match, otherwise - <see langword="false" />.</returns>
    public abstract bool Matches(AbstractCoseKey coseKey);
}
