using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Cryptography.Sign;

/// <summary>
///     Digital signature verifier.
/// </summary>
public interface IDigitalSignatureVerifier
{
    /// <summary>
    ///     Validates the digital signature for the specified data using the public key from the X509v3 certificate according to the specified algorithm.
    /// </summary>
    /// <param name="certificate">The X509v3 certificate, the public key of which will be used to validate the digital signature.</param>
    /// <param name="alg">Digital signature algorithm.</param>
    /// <param name="dataToVerify">The data, the signature of which will be validated.</param>
    /// <param name="signature">The signature to be validated.</param>
    /// <returns>If the parameters and the signature are correct - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    bool IsValidCertificateSign(X509Certificate2 certificate, CoseAlgorithm alg, byte[] dataToVerify, byte[] signature);

    /// <summary>
    ///     Validates the digital signature for the specified data using the specified public key.
    /// </summary>
    /// <param name="coseKey">The public key used to validate the digital signature.</param>
    /// <param name="dataToVerify">The data, the signature of which will be validated.</param>
    /// <param name="signature">The signature to be validated.</param>
    /// <returns>If the parameters and the signature are correct - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    bool IsValidCoseKeySign(AbstractCoseKey coseKey, byte[] dataToVerify, byte[] signature);
}
