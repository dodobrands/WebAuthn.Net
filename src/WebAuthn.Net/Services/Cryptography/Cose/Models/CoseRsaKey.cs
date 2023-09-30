using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;

namespace WebAuthn.Net.Services.Cryptography.Cose.Models;

public class CoseRsaKey : AbstractCoseKey
{
    public CoseRsaKey(CoseAlgorithm alg, byte[] modulusN, byte[] coseExponentE)
    {
        if (!CoseKeyType.RSA.GetSupportedAlgorithms().Contains(alg))
        {
            throw new ArgumentOutOfRangeException(nameof(alg), "The specified 'alg' is not included in the list of permitted values for kty = RSA.");
        }

        ArgumentNullException.ThrowIfNull(modulusN);
        ArgumentNullException.ThrowIfNull(coseExponentE);
        Alg = alg;
        ModulusN = modulusN;
        CoseExponentE = coseExponentE;
        if (!TryGetExponent(coseExponentE, out var exponent))
        {
            throw new ArgumentException($"Invalid value of {nameof(coseExponentE)}", nameof(coseExponentE));
        }

        ExponentE = exponent.Value;
    }

    public override CoseKeyType Kty => CoseKeyType.RSA;
    public override CoseAlgorithm Alg { get; }
    public byte[] ModulusN { get; }
    public byte[] CoseExponentE { get; }
    public uint ExponentE { get; }

    private static bool TryGetExponent(byte[] coseExponent, [NotNullWhen(true)] out uint? exponent)
    {
        if (coseExponent.Length > 4)
        {
            exponent = null;
            return false;
        }

        var bytesToAppend = 4 - coseExponent.Length;
        if (bytesToAppend == 0)
        {
            exponent = BinaryPrimitives.ReadUInt32BigEndian(coseExponent);
            return true;
        }

        Span<byte> coseBigEndianBuffer = stackalloc byte[4];
        for (var i = 0; i < 4; i++)
        {
            coseBigEndianBuffer[i] = 0;
        }

        coseExponent.AsSpan().CopyTo(coseBigEndianBuffer[bytesToAppend..]);
        exponent = BinaryPrimitives.ReadUInt32BigEndian(coseBigEndianBuffer);
        return true;
    }
}
