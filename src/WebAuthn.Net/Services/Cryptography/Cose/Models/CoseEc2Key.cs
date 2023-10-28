using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models;

public class CoseEc2Key : AbstractCoseKey
{
    public CoseEc2Key(CoseAlgorithm alg, CoseEllipticCurve crv, byte[] x, byte[] y)
    {
        // alg
        if (!CoseKeyType.EC2.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), $"The specified '{nameof(alg)}' is not included in the list of permitted values for kty = EC2");
        }

        if (!alg.TryGetSupportedEllipticCurves(out var supportedCurves))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), $"For the specified '{nameof(alg)}', there are no valid '{nameof(crv)}' values");
        }

        Alg = alg;

        // crv
        if (!Enum.IsDefined(typeof(CoseEllipticCurve), crv))
        {
            throw new InvalidEnumArgumentException(nameof(crv), (int) crv, typeof(CoseEllipticCurve));
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

    public override CoseKeyType Kty => CoseKeyType.EC2;
    public override CoseAlgorithm Alg { get; }
    public CoseEllipticCurve Crv { get; }
    public byte[] X { get; }
    public byte[] Y { get; }

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
}
