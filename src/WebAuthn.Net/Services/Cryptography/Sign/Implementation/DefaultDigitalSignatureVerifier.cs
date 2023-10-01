﻿using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Cryptography.Sign.Implementation;

public class DefaultDigitalSignatureVerifier : IDigitalSignatureVerifier
{
    public bool IsValidCertificateSign(X509Certificate2 certificate, CoseAlgorithm alg, byte[] dataToVerify, byte[] signature)
    {
        if (!alg.TryGetCoseKeyType(out var kty))
        {
            return false;
        }

        switch (kty.Value)
        {
            case CoseKeyType.EC2:
                {
                    if (!alg.TryGetSupportedEllipticCurves(out var supportedCurves))
                    {
                        return false;
                    }

                    if (!alg.TryToHashAlgorithmName(out var hashAlgorithmName))
                    {
                        return false;
                    }

                    var ecDsaPubKey = certificate.GetECDsaPublicKey();
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

                    var rsaPublicKey = certificate.GetRSAPublicKey();
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

    public bool IsValidCoseKeySign(AbstractCoseKey coseKey, byte[] dataToVerify, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(coseKey);
        switch (coseKey.Kty)
        {
            case CoseKeyType.EC2:
                {
                    if (coseKey is not CoseEc2Key coseEc2Key)
                    {
                        return false;
                    }

                    if (!coseEc2Key.Alg.TryToHashAlgorithmName(out var hashAlgorithmName))
                    {
                        return false;
                    }

                    if (!coseEc2Key.Alg.TryGetSupportedEllipticCurves(out var supportedCurves))
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
            case CoseKeyType.RSA:
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
                        Exponent = coseRsaKey.CoseExponentE
                    });
                    return rsa.VerifyData(dataToVerify, signature, hashAlgorithmName.Value, padding);
                }
            default:
                return false;
        }
    }

    private static bool TryToCoseCurve(ECCurve ecCurve, [NotNullWhen(true)] out CoseEllipticCurve? coseCurve)
    {
        if (string.IsNullOrEmpty(ecCurve.Oid.Value))
        {
            coseCurve = null;
            return false;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEllipticCurve.P256;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP384.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEllipticCurve.P384;
            return true;
        }

        if (ecCurve.Oid.Value.Equals(ECCurve.NamedCurves.nistP521.Oid.Value, StringComparison.Ordinal))
        {
            coseCurve = CoseEllipticCurve.P521;
            return true;
        }

        coseCurve = null;
        return false;
    }

    private static bool TryToEcCurve(CoseEllipticCurve coseCurve, [NotNullWhen(true)] out ECCurve? ecCurve)
    {
        switch (coseCurve)
        {
            case CoseEllipticCurve.P256:
                {
                    ecCurve = ECCurve.NamedCurves.nistP256;
                    return true;
                }
            case CoseEllipticCurve.P384:
                {
                    ecCurve = ECCurve.NamedCurves.nistP384;
                    return true;
                }
            case CoseEllipticCurve.P521:
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