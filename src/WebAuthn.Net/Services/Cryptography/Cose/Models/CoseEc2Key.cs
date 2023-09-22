using System;
using System.ComponentModel;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models;

public class CoseEc2Key : AbstractCoseKey
{
    public CoseEc2Key(CoseAlgorithm alg, CoseEllipticCurve crv, byte[] x, byte[] y)
    {
        if (!CoseKeyType.EC2.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), "The specified 'alg' is not included in the list of permitted values for kty = EC2.");
        }

        if (!Enum.IsDefined(typeof(CoseEllipticCurve), crv))
        {
            throw new InvalidEnumArgumentException(nameof(crv), (int) crv, typeof(CoseEllipticCurve));
        }

        ArgumentNullException.ThrowIfNull(x);
        ArgumentNullException.ThrowIfNull(y);
        Alg = alg;
        Crv = crv;
        X = x;
        Y = y;
    }

    public override CoseKeyType Kty => CoseKeyType.EC2;
    public override CoseAlgorithm Alg { get; }
    public CoseEllipticCurve Crv { get; }
    public byte[] X { get; }
    public byte[] Y { get; }
}
