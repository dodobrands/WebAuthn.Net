using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     11.2.4.5 TPM2B_PUBLIC_KEY_RSA
/// </summary>
public class RsaUnique : AbstractUnique
{
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected RsaUnique(byte[] buffer)
    {
        Buffer = buffer;
    }

    public byte[] Buffer { get; }

    public static bool TryParseRsaUnique(
        ref Span<byte> buffer,
        [NotNullWhen(true)] out RsaUnique? rsaUnique)
    {
        // 11.2.4.5 TPM2B_PUBLIC_KEY_RSA
        // This sized buffer holds the largest RSA public key supported by the TPM
        // Table 174 — Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure
        // | Parameter                          | Type   | Description
        // | size                               | UINT16 | Size of the buffer. The value of zero is only valid for create.
        // | buffer[size] {: MAX_RSA_KEY_BYTES} | BYTE   | Value
        if (!TryConsume(ref buffer, 2, out var rawSize))
        {
            rsaUnique = null;
            return false;
        }

        var size = BinaryPrimitives.ReadUInt16BigEndian(rawSize);

        if (size == 0)
        {
            rsaUnique = null;
            return false;
        }

        if (!TryConsume(ref buffer, size, out var rawBuffer))
        {
            rsaUnique = null;
            return false;
        }

        var resultBuffer = new byte[size];
        if (!rawBuffer.TryCopyTo(resultBuffer.AsSpan()))
        {
            rsaUnique = null;
            return false;
        }

        rsaUnique = new(resultBuffer);
        return true;
    }

    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected static bool TryConsume(ref Span<byte> input, int bytesToConsume, out Span<byte> consumed)
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
