using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     10.5.3 TPM2B_NAME
/// </summary>
public class Tpm2BName
{
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected Tpm2BName()
    {
        Digest = null;
        Handle = null;
    }

    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected Tpm2BName(TpmtHa digest)
    {
        Digest = digest;
        Handle = null;
    }

    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected Tpm2BName(TpmHandle handle)
    {
        Digest = null;
        Handle = handle;
    }

    public TpmtHa? Digest { get; }

    public TpmHandle? Handle { get; }

    public static bool TryParse(ref Span<byte> buffer, [NotNullWhen(true)] out Tpm2BName? tpm2BName)
    {
        // 10.5.3 TPM2B_NAME
        // This buffer holds a Name for any entity type.
        // The type of Name in the structure is determined by context and the size parameter.
        // If size is four, then the Name is a handle.
        // If size is zero, then no Name is present.
        // Otherwise, the size shall be the size of a TPM_ALG_ID plus the size of the digest produced by the indicated hash algorithm.
        // Table 91 — Definition of TPM2B_NAME Structure
        // | Name                           | Type   | Description
        // | size                           | UINT16 | size of the Name structure
        // | name[size]{:sizeof(TPMU_NAME)} | BYTE   | The Name structure
        // 10.5.2 TPMU_NAME
        // Table 90 — Definition of TPMU_NAME Union <>
        // | Parameter | Type       | Selector | Description
        // | digest    | TPMT_HA    |          | when the Name is a digest
        // | handle    | TPM_HANDLE |          | when the Name is a handle
        // 10.3.2 TPMT_HA
        // Table 79 shows the basic hash-agile structure used in this specification.
        // To handle hash agility, this structure uses the hashAlg parameter to indicate the algorithm used to compute the digest and,
        // by implication, the size of the digest.
        // Table 79 — Definition of TPMT_HA Structure <IN/OUT>
        // | Parameter        | Type           | Description
        // | hashAlg          | +TPMI_ALG_HASH | selector of the hash contained in the digest that implies the size of the digest
        // | [hashAlg] digest | TPMU_HA        | the digest data
        if (!TryConsume(ref buffer, 2, out var rawSize))
        {
            tpm2BName = null;
            return false;
        }

        var size = BinaryPrimitives.ReadUInt16BigEndian(rawSize);
        if (size == 0)
        {
            tpm2BName = new();
            return true;
        }

        if (size == 4)
        {
            if (!TryConsume(ref buffer, 4, out var rawHandle))
            {
                tpm2BName = null;
                return false;
            }

            var handle = BinaryPrimitives.ReadUInt32BigEndian(rawHandle);
            tpm2BName = new(new TpmHandle(handle));
            return true;
        }

        if (size < 4)
        {
            tpm2BName = null;
            return false;
        }

        if (!TryConsume(ref buffer, size, out var rawName))
        {
            tpm2BName = null;
            return false;
        }

        var hashAlg = (TpmAlgIdHash) BinaryPrimitives.ReadUInt16BigEndian(rawName[..2]);
        if (!Enum.IsDefined(hashAlg))
        {
            tpm2BName = null;
            return false;
        }

        var digest = new byte[size - 2];
        var rawDigest = rawName[2..];
        if (!rawDigest.TryCopyTo(digest.AsSpan()))
        {
            tpm2BName = null;
            return false;
        }

        tpm2BName = new(new TpmtHa(hashAlg, digest));
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
