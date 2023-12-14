using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.OKP;

namespace WebAuthn.Net.Services.Serialization.Cose.Models;

/// <summary>
///     Public key in COSE OKP format.
/// </summary>
public class CoseOkpKey : AbstractCoseKey
{
    /// <summary>
    ///     Constructs <see cref="CoseOkpKey" />.
    /// </summary>
    /// <param name="alg">The identifier of the cryptographic algorithm of this public key.</param>
    /// <param name="crv">COSE elliptic curve for a public key in OKP format.</param>
    /// <param name="x">Public Key.</param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="alg" /> is not in the range of supported algorithms for public keys in OKP format</exception>
    /// <exception cref="ArgumentOutOfRangeException">For the specified <paramref name="alg" />, it was not possible to determine the list of supported elliptic curves</exception>
    /// <exception cref="InvalidEnumArgumentException"><paramref name="crv" /> contains a value that is not defined in <see cref="CoseOkpEllipticCurve" /></exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="crv" /> is not in the allowed values for the specified <paramref name="alg" /></exception>
    /// <exception cref="ArgumentNullException"><paramref name="x" /> is <see langword="null" /></exception>
    public CoseOkpKey(CoseAlgorithm alg, CoseOkpEllipticCurve crv, byte[] x)
    {
        // alg
        if (!CoseKeyType.OKP.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), $"The specified '{nameof(alg)}' is not included in the list of permitted values for kty = EC2");
        }

        if (!alg.TryGetOkpSupportedEllipticCurves(out var supportedCurves))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), $"For the specified '{nameof(alg)}', there are no valid '{nameof(crv)}' values");
        }

        Alg = alg;

        // crv
        if (!Enum.IsDefined(typeof(CoseOkpEllipticCurve), crv))
        {
            throw new InvalidEnumArgumentException(nameof(crv), (int) crv, typeof(CoseOkpEllipticCurve));
        }

        if (!supportedCurves.Contains(crv))
        {
            throw new ArgumentOutOfRangeException(nameof(crv), $"The specified '{nameof(crv)}' is not included in the list of valid values for '{nameof(alg)}'");
        }

        Crv = crv;

        // x
        ArgumentNullException.ThrowIfNull(x);
        X = x;
    }

    /// <inheritdoc />
    public override CoseKeyType Kty => CoseKeyType.OKP;

    /// <inheritdoc />
    public override CoseAlgorithm Alg { get; }

    /// <summary>
    ///     COSE elliptic curve for a public key in OKP format.
    /// </summary>
    public CoseOkpEllipticCurve Crv { get; }

    /// <summary>
    ///     Public Key.
    /// </summary>
    public byte[] X { get; }

    /// <inheritdoc />
    public override bool Matches(X509Certificate2 certificate)
    {
        // https://github.com/dotnet/runtime/issues/14741
        // https://github.com/dotnet/runtime/issues/63174
        // https://github.com/dotnet/runtime/issues/81433
        // This format is required for EdDSA (Ed25519) support.
        // But .NET itself does not currently support Ed25519, so this functionality is implemented through a third-party library.
        return false;
    }

    /// <inheritdoc />
    public override bool Matches(AsymmetricAlgorithm asymmetricAlgorithm)
    {
        // https://github.com/dotnet/runtime/issues/14741
        // https://github.com/dotnet/runtime/issues/63174
        // https://github.com/dotnet/runtime/issues/81433
        // This format is required for EdDSA (Ed25519) support.
        // But .NET itself does not currently support Ed25519, so this functionality is implemented through a third-party library.
        return false;
    }

    /// <inheritdoc />
    public override bool Matches(AbstractCoseKey coseKey)
    {
        if (coseKey is not CoseOkpKey other)
        {
            return false;
        }

        return other.Kty == Kty
               && other.Alg == Alg
               && other.Crv == Crv
               && other.X.AsSpan().SequenceEqual(X.AsSpan());
    }
}
