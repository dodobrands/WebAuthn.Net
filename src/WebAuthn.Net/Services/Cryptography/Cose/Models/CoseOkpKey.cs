using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.OKP;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models;

public class CoseOkpKey : AbstractCoseKey
{
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

    /// <summary>
    ///     Identification of the key type
    /// </summary>
    public override CoseKeyType Kty => CoseKeyType.OKP;

    /// <summary>
    ///     Key usage restriction to this algorithm
    /// </summary>
    public override CoseAlgorithm Alg { get; }

    /// <summary>
    ///     EC identifier.
    /// </summary>
    public CoseOkpEllipticCurve Crv { get; }

    /// <summary>
    ///     Public Key
    /// </summary>
    public byte[] X { get; }

    public override bool Matches(X509Certificate2 certificate)
    {
        // https://github.com/dotnet/runtime/issues/14741
        // https://github.com/dotnet/runtime/issues/63174
        // https://github.com/dotnet/runtime/issues/81433
        // This format is required for EdDSA (Ed25519) support.
        // But .NET itself does not currently support Ed25519, so this functionality is implemented through a third-party library.
        return false;
    }

    public override bool Matches(AsymmetricAlgorithm asymmetricAlgorithm)
    {
        // https://github.com/dotnet/runtime/issues/14741
        // https://github.com/dotnet/runtime/issues/63174
        // https://github.com/dotnet/runtime/issues/81433
        // This format is required for EdDSA (Ed25519) support.
        // But .NET itself does not currently support Ed25519, so this functionality is implemented through a third-party library.
        return false;
    }

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
