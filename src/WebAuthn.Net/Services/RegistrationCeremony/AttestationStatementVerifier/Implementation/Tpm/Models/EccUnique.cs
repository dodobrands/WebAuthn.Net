using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models;

/// <summary>
///     11.2.5.2 TPMS_ECC_POINT
/// </summary>
public class EccUnique : AbstractUnique
{
    public EccUnique(byte[] x, byte[] y)
    {
        X = x;
        Y = y;
    }

    public byte[] X { get; }
    public byte[] Y { get; }

    public static bool TryParseEccUnique(
        ref Span<byte> buffer,
        [NotNullWhen(true)] out EccUnique? eccUnique)
    {
        // 11.2.5.2 TPMS_ECC_POINT
        // This structure holds two ECC coordinates that, together, make up an ECC point.
        // Table 178 — Definition of {ECC} TPMS_ECC_POINT Structure
        // | Parameter | Type                | Description
        // | x         | TPM2B_ECC_PARAMETER | X coordinate
        // | y         | TPM2B_ECC_PARAMETER | Y coordinate

        // 11.2.5.1 TPM2B_ECC_PARAMETER
        // Table 177 — Definition of TPM2B_ECC_PARAMETER Structure
        // | Parameter                         | Type   | Description
        // | size                              | UINT16 | Size of buffer
        // | buffer[size] {:MAX_ECC_KEY_BYTES} | BYTE   | The parameter data

        // x.size
        if (!TryConsume(ref buffer, 2, out var rawXSize))
        {
            eccUnique = null;
            return false;
        }

        var xSize = BinaryPrimitives.ReadUInt16BigEndian(rawXSize);
        if (xSize == 0)
        {
            eccUnique = null;
            return false;
        }

        // x.buffer
        if (!TryConsume(ref buffer, xSize, out var rawX))
        {
            eccUnique = null;
            return false;
        }

        var x = new byte[xSize];
        if (!rawX.TryCopyTo(x.AsSpan()))
        {
            eccUnique = null;
            return false;
        }

        // y.size
        if (!TryConsume(ref buffer, 2, out var rawYSize))
        {
            eccUnique = null;
            return false;
        }

        var ySize = BinaryPrimitives.ReadUInt16BigEndian(rawYSize);
        if (ySize == 0)
        {
            eccUnique = null;
            return false;
        }

        // y.buffer
        if (!TryConsume(ref buffer, ySize, out var rawY))
        {
            eccUnique = null;
            return false;
        }

        var y = new byte[ySize];
        if (!rawY.TryCopyTo(y.AsSpan()))
        {
            eccUnique = null;
            return false;
        }

        eccUnique = new(x, y);
        return true;
    }

    private static bool TryConsume(ref Span<byte> input, int bytesToConsume, out Span<byte> consumed)
    {
        if (input.Length < bytesToConsume)
        {
            consumed = default;
            return false;
        }

        consumed = input[..bytesToConsume];
        input = input[bytesToConsume..];
        return true;
    }
}
