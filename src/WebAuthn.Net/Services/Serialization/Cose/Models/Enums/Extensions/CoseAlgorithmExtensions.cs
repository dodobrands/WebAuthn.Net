using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;

namespace WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;

/// <summary>
///     Extension methods for <see cref="CoseAlgorithm" />.
/// </summary>
public static class CoseAlgorithmIdentifierExtensions
{
    private static readonly IReadOnlySet<CoseEc2EllipticCurve> Es512 = new HashSet<CoseEc2EllipticCurve>
    {
        CoseEc2EllipticCurve.P521
    };

    private static readonly IReadOnlySet<CoseEc2EllipticCurve> Es384 = new HashSet<CoseEc2EllipticCurve>
    {
        CoseEc2EllipticCurve.P384
    };

    private static readonly IReadOnlySet<CoseEc2EllipticCurve> Es256 = new HashSet<CoseEc2EllipticCurve>
    {
        CoseEc2EllipticCurve.P256
    };

    private static readonly IReadOnlySet<CoseOkpEllipticCurve> EdDsa = new HashSet<CoseOkpEllipticCurve>
    {
        CoseOkpEllipticCurve.Ed25519
    };

    /// <summary>
    ///     If possible, returns for the specified algorithm a set of supported elliptic curves for public keys in COSE EC2 format.
    /// </summary>
    /// <param name="coseAlgorithm">The algorithm for which a set of supported elliptic curves is obtained.</param>
    /// <param name="ellipticCurves">
    ///     Output parameter. Contains a set of supported elliptic curves for the specified <paramref name="coseAlgorithm" /> if the method returns <see langword="true" />. If the method returns <see langword="false" />, it means there are no supported elliptic
    ///     curves for the specified <paramref name="coseAlgorithm" />, and the value of this parameter will be <see langword="null" />.
    /// </param>
    /// <returns><see langword="true" /> if a set of supported elliptic curves exists for the <paramref name="coseAlgorithm" />, otherwise - <see langword="false" />.</returns>
    public static bool TryGetEc2SupportedEllipticCurves(
        this CoseAlgorithm coseAlgorithm,
        [NotNullWhen(true)] out IReadOnlySet<CoseEc2EllipticCurve>? ellipticCurves)
    {
        switch (coseAlgorithm)
        {
            case CoseAlgorithm.ES512:
                {
                    ellipticCurves = Es512;
                    return true;
                }
            case CoseAlgorithm.ES384:
                {
                    ellipticCurves = Es384;
                    return true;
                }
            case CoseAlgorithm.ES256:
                {
                    ellipticCurves = Es256;
                    return true;
                }
            default:
                {
                    ellipticCurves = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     If possible, returns for the specified algorithm a set of supported elliptic curves for public keys in COSE OKP format.
    /// </summary>
    /// <param name="coseAlgorithm">The algorithm for which a set of supported elliptic curves is obtained.</param>
    /// <param name="ellipticCurves">
    ///     Output parameter. Contains a set of supported elliptic curves for the specified <paramref name="coseAlgorithm" /> if the method returns <see langword="true" />. If the method returns <see langword="false" />, it means there are no supported elliptic
    ///     curves for the specified <paramref name="coseAlgorithm" />, and the value of this parameter will be <see langword="null" />.
    /// </param>
    /// <returns><see langword="true" /> if a set of supported elliptic curves exists for the <paramref name="coseAlgorithm" />, otherwise - <see langword="false" />.</returns>
    public static bool TryGetOkpSupportedEllipticCurves(
        this CoseAlgorithm coseAlgorithm,
        [NotNullWhen(true)] out IReadOnlySet<CoseOkpEllipticCurve>? ellipticCurves)
    {
        if (coseAlgorithm == CoseAlgorithm.EdDSA)
        {
            ellipticCurves = EdDsa;
            return true;
        }

        ellipticCurves = null;
        return false;
    }

    /// <summary>
    ///     If possible, it determines the COSE key type for the specified algorithm.
    /// </summary>
    /// <param name="coseAlgorithm">The algorithm for which the COSE key type needs to be determined</param>
    /// <param name="kty">Output parameter. Contains the COSE key type if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if it was possible to determine the COSE key type for the specified <paramref name="coseAlgorithm" />, otherwise <see langword="false" />.</returns>
    public static bool TryGetCoseKeyType(
        this CoseAlgorithm coseAlgorithm,
        [NotNullWhen(true)] out CoseKeyType? kty)
    {
        switch (coseAlgorithm)
        {
            case CoseAlgorithm.RS1:
                {
                    kty = CoseKeyType.RSA;
                    return true;
                }
            case CoseAlgorithm.RS512:
                {
                    kty = CoseKeyType.RSA;
                    return true;
                }
            case CoseAlgorithm.RS384:
                {
                    kty = CoseKeyType.RSA;
                    return true;
                }
            case CoseAlgorithm.RS256:
                {
                    kty = CoseKeyType.RSA;
                    return true;
                }
            case CoseAlgorithm.PS512:
                {
                    kty = CoseKeyType.RSA;
                    return true;
                }
            case CoseAlgorithm.PS384:
                {
                    kty = CoseKeyType.RSA;
                    return true;
                }
            case CoseAlgorithm.PS256:
                {
                    kty = CoseKeyType.RSA;
                    return true;
                }
            case CoseAlgorithm.ES512:
                {
                    kty = CoseKeyType.EC2;
                    return true;
                }
            case CoseAlgorithm.ES384:
                {
                    kty = CoseKeyType.EC2;
                    return true;
                }
            case CoseAlgorithm.ES256:
                {
                    kty = CoseKeyType.EC2;
                    return true;
                }
            case CoseAlgorithm.EdDSA:
                {
                    kty = CoseKeyType.OKP;
                    return true;
                }
            default:
                {
                    kty = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     If possible, determines the <see cref="HashAlgorithmName" /> for the specified algorithm.
    /// </summary>
    /// <param name="coseAlgorithm">The algorithm for which the <see cref="HashAlgorithmName" /> needs to be determined.</param>
    /// <param name="alg">Output parameter. Contains the <see cref="HashAlgorithmName" /> if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if it was possible to determine the <see cref="HashAlgorithmName" /> for the specified <paramref name="coseAlgorithm" />, otherwise <see langword="false" />.</returns>
    public static bool TryToHashAlgorithmName(
        this CoseAlgorithm coseAlgorithm,
        [NotNullWhen(true)] out HashAlgorithmName? alg)
    {
        switch (coseAlgorithm)
        {
            case CoseAlgorithm.RS1:
                {
                    alg = HashAlgorithmName.SHA1;
                    return true;
                }
            case CoseAlgorithm.RS512:
                {
                    alg = HashAlgorithmName.SHA512;
                    return true;
                }
            case CoseAlgorithm.RS384:
                {
                    alg = HashAlgorithmName.SHA384;
                    return true;
                }
            case CoseAlgorithm.RS256:
                {
                    alg = HashAlgorithmName.SHA256;
                    return true;
                }
            case CoseAlgorithm.PS512:
                {
                    alg = HashAlgorithmName.SHA512;
                    return true;
                }
            case CoseAlgorithm.PS384:
                {
                    alg = HashAlgorithmName.SHA384;
                    return true;
                }
            case CoseAlgorithm.PS256:
                {
                    alg = HashAlgorithmName.SHA256;
                    return true;
                }
            case CoseAlgorithm.ES512:
                {
                    alg = HashAlgorithmName.SHA512;
                    return true;
                }
            case CoseAlgorithm.ES384:
                {
                    alg = HashAlgorithmName.SHA384;
                    return true;
                }
            case CoseAlgorithm.ES256:
                {
                    alg = HashAlgorithmName.SHA256;
                    return true;
                }
            default:
                {
                    alg = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     If possible, computes the hash using the specified algorithm.
    /// </summary>
    /// <param name="coseAlgorithm">The algorithm with which the hash will be computed.</param>
    /// <param name="data">The data for which the hash needs to be computed.</param>
    /// <param name="hash">Output parameter. Contains the computed hash if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if it is possible to compute a hash for the specified algorithm, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms")]
    public static bool TryComputeHash(
        this CoseAlgorithm coseAlgorithm,
        ReadOnlySpan<byte> data,
        [NotNullWhen(true)] out byte[]? hash)
    {
        switch (coseAlgorithm)
        {
            case CoseAlgorithm.RS1:
                {
                    hash = SHA1.HashData(data);
                    return true;
                }
            case CoseAlgorithm.RS512:
                {
                    hash = SHA512.HashData(data);
                    return true;
                }
            case CoseAlgorithm.RS384:
                {
                    hash = SHA384.HashData(data);
                    return true;
                }
            case CoseAlgorithm.RS256:
                {
                    hash = SHA256.HashData(data);
                    return true;
                }
            case CoseAlgorithm.PS512:
                {
                    hash = SHA512.HashData(data);
                    return true;
                }
            case CoseAlgorithm.PS384:
                {
                    hash = SHA384.HashData(data);
                    return true;
                }
            case CoseAlgorithm.PS256:
                {
                    hash = SHA256.HashData(data);
                    return true;
                }
            case CoseAlgorithm.ES512:
                {
                    hash = SHA512.HashData(data);
                    return true;
                }
            case CoseAlgorithm.ES384:
                {
                    hash = SHA384.HashData(data);
                    return true;
                }
            case CoseAlgorithm.ES256:
                {
                    hash = SHA256.HashData(data);
                    return true;
                }
            default:
                {
                    hash = null;
                    return false;
                }
        }
    }

    /// <summary>
    ///     If possible, returns the RSA padding mode for the specified algorithm.
    /// </summary>
    /// <param name="coseAlgorithm">The algorithm for which the RSA padding mode needs to be returned.</param>
    /// <param name="padding">Output parameter. Contains the RSA padding mode if the method returns <see langword="true" />, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if an RSA padding mode exists for the specified algorithm, otherwise - <see langword="false" />.</returns>
    public static bool TryGetRsaPadding(
        this CoseAlgorithm coseAlgorithm,
        [NotNullWhen(true)] out RSASignaturePadding? padding)
    {
        switch (coseAlgorithm)
        {
            case CoseAlgorithm.RS1:
            case CoseAlgorithm.RS512:
            case CoseAlgorithm.RS384:
            case CoseAlgorithm.RS256:
                {
                    padding = RSASignaturePadding.Pkcs1;
                    return true;
                }
            case CoseAlgorithm.PS512:
            case CoseAlgorithm.PS384:
            case CoseAlgorithm.PS256:
                {
                    padding = RSASignaturePadding.Pss;
                    return true;
                }
            default:
                {
                    padding = null;
                    return false;
                }
        }
    }
}
