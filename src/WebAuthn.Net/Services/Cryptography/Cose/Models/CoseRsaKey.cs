using System;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models;

public class CoseRsaKey : AbstractCoseKey
{
    public CoseRsaKey(CoseAlgorithm alg, byte[] n, byte[] e)
    {
        if (!CoseKeyType.RSA.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), "The specified 'alg' is not included in the list of permitted values for kty = RSA.");
        }

        ArgumentNullException.ThrowIfNull(n);
        ArgumentNullException.ThrowIfNull(e);
        Alg = alg;
        N = n;
        E = e;
    }

    public override CoseKeyType Kty => CoseKeyType.RSA;
    public override CoseAlgorithm Alg { get; }
    public byte[] N { get; }
    public byte[] E { get; }
}
