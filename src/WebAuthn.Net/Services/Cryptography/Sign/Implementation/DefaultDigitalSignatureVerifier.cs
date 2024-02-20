using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Cryptography.Sign.Implementation;

/// <summary>
///     Default implementation of <see cref="IDigitalSignatureVerifier" />.
/// </summary>
public class DefaultDigitalSignatureVerifier : IDigitalSignatureVerifier
{
    /// <inheritdoc />
    public virtual bool IsValidCertificateSign(X509Certificate2 certificate, CoseAlgorithm alg, byte[] dataToVerify, byte[] signature)
    {
        if (!alg.TryGetCoseKeyType(out var kty))
        {
            return false;
        }

        switch (kty.Value)
        {
            case CoseKeyType.EC2:
                {
                    if (!alg.TryGetEc2SupportedEllipticCurves(out var supportedCurves))
                    {
                        return false;
                    }

                    if (!alg.TryToHashAlgorithmName(out var hashAlgorithmName))
                    {
                        return false;
                    }

                    using var ecDsaPubKey = certificate.GetECDsaPublicKey();
                    if (ecDsaPubKey is null)
                    {
                        return false;
                    }

                    var keyParams = ecDsaPubKey.ExportParameters(false);
                    var curve = keyParams.Curve;
                    if (!TryToCoseCurve(curve, out var coseCurve))
                    {
                        return false;
                    }

                    if (!supportedCurves.Contains(coseCurve.Value))
                    {
                        return false;
                    }

                    var x = keyParams.Q.X;
                    var y = keyParams.Q.Y;
                    if (x is null || y is null)
                    {
                        return false;
                    }

                    var point = new ECPoint
                    {
                        X = x,
                        Y = y
                    };

                    using var ecdsa = ECDsa.Create(new ECParameters
                    {
                        Q = point,
                        Curve = curve
                    });
                    return ecdsa.VerifyData(dataToVerify, signature, hashAlgorithmName.Value, DSASignatureFormat.Rfc3279DerSequence);
                }
            case CoseKeyType.RSA:
                {
                    if (!alg.TryToHashAlgorithmName(out var hashAlgorithmName))
                    {
                        return false;
                    }

                    if (!alg.TryGetRsaPadding(out var padding))
                    {
                        return false;
                    }

                    using var rsaPublicKey = certificate.GetRSAPublicKey();
                    if (rsaPublicKey is null)
                    {
                        return false;
                    }

                    var keyParams = rsaPublicKey.ExportParameters(false);
                    var modulus = keyParams.Modulus;
                    var exponent = keyParams.Exponent;
                    if (modulus is null || exponent is null)
                    {
                        return false;
                    }

                    using var rsa = RSA.Create(new RSAParameters
                    {
                        Modulus = modulus,
                        Exponent = exponent
                    });
                    return rsa.VerifyData(dataToVerify, signature, hashAlgorithmName.Value, padding);
                }
            default:
                return false;
        }
    }

    /// <inheritdoc />
    public virtual bool IsValidCoseKeySign(AbstractCoseKey coseKey, byte[] dataToVerify, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(coseKey);
        switch (coseKey.Kty)
        {
            case CoseKeyType.EC2:
                {
                    return IsValidCoseKeySignEc2(coseKey, dataToVerify, signature);
                }
            case CoseKeyType.RSA:
                {
                    return IsValidCoseKeySignRsa(coseKey, dataToVerify, signature);
                }
            case CoseKeyType.OKP:
                {
                    return IsValidCoseKeySignOkp(coseKey, dataToVerify, signature);
                }
            default:
                return false;
        }
    }

    /// <summary>
    ///     Verifies the digital signature for a key in EC2 format.
    /// </summary>
    /// <param name="coseKey">Public key in EC2 format.</param>
    /// <param name="dataToVerify">The data, the signature of which will be validated.</param>
    /// <param name="signature">The signature to be validated.</param>
    /// <returns>If the parameters and the signature are correct - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsValidCoseKeySignEc2(AbstractCoseKey coseKey, byte[] dataToVerify, byte[] signature)
    {
        if (coseKey is not CoseEc2Key coseEc2Key)
        {
            return false;
        }

        if (!coseEc2Key.Alg.TryToHashAlgorithmName(out var hashAlgorithmName))
        {
            return false;
        }

        if (!coseEc2Key.Alg.TryGetEc2SupportedEllipticCurves(out var supportedCurves))
        {
            return false;
        }

        if (!supportedCurves.Contains(coseEc2Key.Crv))
        {
            return false;
        }

        if (!TryToEcCurve(coseEc2Key.Crv, out var ecCurve))
        {
            return false;
        }

        var point = new ECPoint
        {
            X = coseEc2Key.X,
            Y = coseEc2Key.Y
        };
        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Q = point,
            Curve = ecCurve.Value
        });
        return ecdsa.VerifyData(dataToVerify, signature, hashAlgorithmName.Value, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    ///     Verifies the digital signature for a key in RSA format.
    /// </summary>
    /// <param name="coseKey">Public key in RSA format.</param>
    /// <param name="dataToVerify">The data, the signature of which will be validated.</param>
    /// <param name="signature">The signature to be validated.</param>
    /// <returns>If the parameters and the signature are correct - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsValidCoseKeySignRsa(AbstractCoseKey coseKey, byte[] dataToVerify, byte[] signature)
    {
        if (coseKey is not CoseRsaKey coseRsaKey)
        {
            return false;
        }

        if (!coseRsaKey.Alg.TryToHashAlgorithmName(out var hashAlgorithmName))
        {
            return false;
        }

        if (!coseRsaKey.Alg.TryGetRsaPadding(out var padding))
        {
            return false;
        }

        using var rsa = RSA.Create(new RSAParameters
        {
            Modulus = coseRsaKey.ModulusN,
            Exponent = coseRsaKey.ExponentE
        });
        return rsa.VerifyData(dataToVerify, signature, hashAlgorithmName.Value, padding);
    }

    /// <summary>
    ///     Verifies the digital signature for a key in OKP format.
    /// </summary>
    /// <param name="coseKey">Public key in OKP format.</param>
    /// <param name="dataToVerify">The data, the signature of which will be validated.</param>
    /// <param name="signature">The signature to be validated.</param>
    /// <returns>If the parameters and the signature are correct - <see langword="true" />, otherwise - <see langword="false" />.</returns>
    protected virtual bool IsValidCoseKeySignOkp(AbstractCoseKey coseKey, byte[] dataToVerify, byte[] signature)
    {
        if (coseKey is not CoseOkpKey coseOkpKey)
        {
            return false;
        }

        if (!coseOkpKey.Alg.TryGetOkpSupportedEllipticCurves(out var supportedCurves))
        {
            return false;
        }

        if (!supportedCurves.Contains(coseOkpKey.Crv))
        {
            return false;
        }

        if (coseOkpKey.Alg != CoseAlgorithm.EdDSA || coseOkpKey.Crv != CoseOkpEllipticCurve.Ed25519)
        {
            return false;
        }

        return Ed25519.Verify(coseOkpKey.X, dataToVerify, signature);
    }

    private static bool TryToCoseCurve(ECCurve ecCurve, [NotNullWhen(true)] out CoseEc2EllipticCurve? coseCurve)
    {
        if (string.IsNullOrEmpty(ecCurve.Oid.Value))
        {
            coseCurve = null;
            return false;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEc2EllipticCurve.P256;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEc2EllipticCurve.P384;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEc2EllipticCurve.P521;
            return true;
        }

        coseCurve = null;
        return false;
    }

    private static bool TryToEcCurve(CoseEc2EllipticCurve coseEc2Curve, [NotNullWhen(true)] out ECCurve? ecCurve)
    {
        switch (coseEc2Curve)
        {
            case CoseEc2EllipticCurve.P256:
                {
                    ecCurve = ECCurve.NamedCurves.nistP256;
                    return true;
                }
            case CoseEc2EllipticCurve.P384:
                {
                    ecCurve = ECCurve.NamedCurves.nistP384;
                    return true;
                }
            case CoseEc2EllipticCurve.P521:
                {
                    ecCurve = ECCurve.NamedCurves.nistP521;
                    return true;
                }
            default:
                {
                    ecCurve = null;
                    return false;
                }
        }
    }
}
