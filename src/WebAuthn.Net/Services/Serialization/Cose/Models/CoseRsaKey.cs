using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

/// <summary>
///     Public key in COSE RSA format.
/// </summary>
public class CoseRsaKey : AbstractCoseKey
{
    /// <summary>
    ///     Constructs <see cref="CoseRsaKey" />.
    /// </summary>
    /// <param name="alg">The identifier of the cryptographic algorithm of this public key.</param>
    /// <param name="modulusN">RSA modulus N.</param>
    /// <param name="exponentE">RSA exponent E.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="alg" /> is not in the range of supported algorithms for public keys in RSA format</exception>
    /// <exception cref="ArgumentNullException"><paramref name="modulusN" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="exponentE" /> is <see langword="null" /></exception>
    public CoseRsaKey(CoseAlgorithm alg, byte[] modulusN, byte[] exponentE)
    {
        // alg
        if (!CoseKeyType.RSA.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), "The specified 'alg' is not included in the list of permitted values for kty = RSA.");
        }

        Alg = alg;

        // modulusN
        ArgumentNullException.ThrowIfNull(modulusN);
        ModulusN = modulusN;

        // exponentE
        ArgumentNullException.ThrowIfNull(exponentE);
        ExponentE = exponentE;
    }

    /// <inheritdoc />
    public override CoseKeyType Kty => CoseKeyType.RSA;

    /// <inheritdoc />
    public override CoseAlgorithm Alg { get; }

    /// <summary>
    ///     RSA modulus N.
    /// </summary>
    public byte[] ModulusN { get; }

    /// <summary>
    ///     RSA exponent E.
    /// </summary>
    public byte[] ExponentE { get; }

    /// <inheritdoc />
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    public override bool Matches(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            return false;
        }

        using var certRsa = certificate.GetRSAPublicKey();
        if (certRsa is null)
        {
            return false;
        }

        var certParams = certRsa.ExportParameters(false);
        var certModulus = certParams.Modulus;
        var certExponent = certParams.Exponent;
        if (certModulus is null || certExponent is null)
        {
            return false;
        }

        return certModulus.AsSpan().SequenceEqual(ModulusN.AsSpan())
               && certExponent.AsSpan().SequenceEqual(ExponentE.AsSpan());
    }

    /// <inheritdoc />
    public override bool Matches(AsymmetricAlgorithm asymmetricAlgorithm)
    {
        if (asymmetricAlgorithm is not RSA alg)
        {
            return false;
        }

        var algParams = alg.ExportParameters(false);
        var algModulus = algParams.Modulus;
        var algExponent = algParams.Exponent;
        if (algModulus is null || algExponent is null)
        {
            return false;
        }

        return algModulus.AsSpan().SequenceEqual(ModulusN.AsSpan())
               && algExponent.AsSpan().SequenceEqual(ExponentE.AsSpan());
    }

    /// <inheritdoc />
    public override bool Matches(AbstractCoseKey coseKey)
    {
        if (coseKey is not CoseRsaKey other)
        {
            return false;
        }

        return other.Kty == Kty
               && other.Alg == Alg
               && other.ModulusN.AsSpan().SequenceEqual(ModulusN.AsSpan())
               && other.ExponentE.AsSpan().SequenceEqual(ExponentE.AsSpan());
    }
}
