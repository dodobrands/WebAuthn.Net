using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

/// <summary>
///     Public key in COSE EC2 format.
/// </summary>
public class CoseEc2Key : AbstractCoseKey
{
    /// <summary>
    ///     Constructs <see cref="CoseEc2Key" />.
    /// </summary>
    /// <param name="alg">The identifier of the cryptographic algorithm of this public key.</param>
    /// <param name="crv">COSE elliptic curve for a public key in EC2 format.</param>
    /// <param name="x">X coordinate.</param>
    /// <param name="y">Y coordinate.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="alg" /> is not in the range of supported algorithms for public keys in EC2 format</exception>
    /// <exception cref="ArgumentOutOfRangeException">For the specified <paramref name="alg" />, it was not possible to determine the list of supported elliptic curves</exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="crv" /> contains a value that is not defined in <see cref="CoseEc2EllipticCurve" /></exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="crv" /> is not in the allowed values for the specified <paramref name="alg" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="x" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="y" /> is <see langword="null" /></exception>
    public CoseEc2Key(CoseAlgorithm alg, CoseEc2EllipticCurve crv, byte[] x, byte[] y)
    {
        // alg
        if (!CoseKeyType.EC2.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), $"The specified '{nameof(alg)}' is not included in the list of permitted values for kty = EC2");
        }

        if (!alg.TryGetEc2SupportedEllipticCurves(out var supportedCurves))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), $"For the specified '{nameof(alg)}', there are no valid '{nameof(crv)}' values");
        }

        Alg = alg;

        // crv
        if (!Enum.IsDefined(typeof(CoseEc2EllipticCurve), crv))
        {
            throw new InvalidEnumArgumentException(nameof(crv), (int) crv, typeof(CoseEc2EllipticCurve));
        }

        if (!supportedCurves.Contains(crv))
        {
            throw new ArgumentOutOfRangeException(nameof(crv), $"The specified '{nameof(crv)}' is not included in the list of valid values for '{nameof(alg)}'");
        }

        Crv = crv;

        // x
        ArgumentNullException.ThrowIfNull(x);
        X = x;

        // y
        ArgumentNullException.ThrowIfNull(y);
        Y = y;
    }

    /// <inheritdoc />
    public override CoseKeyType Kty => CoseKeyType.EC2;

    /// <inheritdoc />
    public override CoseAlgorithm Alg { get; }

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

    /// <inheritdoc />
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    public override bool Matches(X509Certificate2 certificate)
    {
        if (certificate is null)
        {
            return false;
        }

        using var certEcdsa = certificate.GetECDsaPublicKey();
        if (certEcdsa is null)
        {
            return false;
        }

        var certParams = certEcdsa.ExportParameters(false);
        if (!TryToCoseCurve(certParams.Curve, out var certCurve))
        {
            return false;
        }

        var certX = certParams.Q.X;
        var certY = certParams.Q.Y;
        return certCurve.Value == Crv
               && certX.AsSpan().SequenceEqual(X.AsSpan())
               && certY.AsSpan().SequenceEqual(Y.AsSpan());
    }

    /// <inheritdoc />
    public override bool Matches(AsymmetricAlgorithm asymmetricAlgorithm)
    {
        if (asymmetricAlgorithm is not ECDsa alg)
        {
            return false;
        }

        var algParams = alg.ExportParameters(false);
        if (!TryToCoseCurve(algParams.Curve, out var algCurve))
        {
            return false;
        }

        var algX = algParams.Q.X;
        var algY = algParams.Q.Y;
        return algCurve.Value == Crv
               && algX.AsSpan().SequenceEqual(X.AsSpan())
               && algY.AsSpan().SequenceEqual(Y.AsSpan());
    }

    /// <inheritdoc />
    public override bool Matches(AbstractCoseKey coseKey)
    {
        if (coseKey is not CoseEc2Key other)
        {
            return false;
        }

        return other.Kty == Kty
               && other.Alg == Alg
               && other.Crv == Crv
               && other.X.AsSpan().SequenceEqual(X.AsSpan())
               && other.Y.AsSpan().SequenceEqual(Y.AsSpan());
    }

    /// <summary>
    ///     If possible, converts the built-in .NET type <see cref="ECCurve" /> value to a value of the <see cref="CoseEc2EllipticCurve" /> enum.
    /// </summary>
    /// <param name="ecCurve">The <see cref="ECCurve" /> value that needs to be converted to the <see cref="CoseEc2EllipticCurve" /> enum.</param>
    /// <param name="coseCurve">Output parameter. If the method returns <see langword="true" />, the conversion was successful and it then contains a value from the <see cref="CoseEc2EllipticCurve" /> enum, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" />, if the conversion was successful, otherwise - <see langword="false" />.</returns>
    protected static bool TryToCoseCurve(ECCurve ecCurve, [NotNullWhen(true)] out CoseEc2EllipticCurve? coseCurve)
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
}
