using System;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models;

public class CoseRsaKey : AbstractCoseKey
{
    public CoseRsaKey(CoseAlgorithm alg, byte[] modulusN, byte[] publicExponentE)
    {
        if (!CoseKeyType.RSA.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), "The specified 'alg' is not included in the list of permitted values for kty = RSA.");
        }

        ArgumentNullException.ThrowIfNull(modulusN);
        ArgumentNullException.ThrowIfNull(publicExponentE);
        Alg = alg;
        ModulusN = modulusN;
        PublicExponentE = publicExponentE;
    }

    public override CoseKeyType Kty => CoseKeyType.RSA;
    public override CoseAlgorithm Alg { get; }
    public byte[] ModulusN { get; }
    public byte[] PublicExponentE { get; }
}
