using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     12.2.3.5 TPMS_RSA_PARMS
/// </summary>
public class RsaParms : AbstractPublicParms
{
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected RsaParms(ushort keyBits, uint exponent)
    {
        KeyBits = keyBits;
        Exponent = exponent;
    }

    public ushort KeyBits { get; }
    public uint Exponent { get; }

    public static bool TryParseRsaParms(
        ref Span<byte> buffer,
        ObjectAttributes objectAttributes,
        [NotNullWhen(true)] out RsaParms? rsaDetail)
    {
        // 12.2.3.5 TPMS_RSA_PARMS
        // A TPM compatible with this specification and supporting RSA shall support two primes and an exponent of zero.
        // An exponent of zero indicates that the exponent is the default of 2^16 + 1.
        // Support for other values is optional.
        // Use of other exponents in duplicated keys is not recommended because the resulting keys would not be interoperable with other TPMs.
        // Table 196 — Definition of {RSA} TPMS_RSA_PARMS Structure
        // | Parameter | Type                 | Description
        // | symmetric | TPMT_SYM_DEF_OBJECT+ | For a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode. if the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        // | scheme    | TPMT_RSA_SCHEME+     | scheme.scheme shall be:
        // |           |                      | - for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
        // |           |                      | - for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
        // |           |                      | - for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL unless the object also has the sign attribute for a restricted decryption key, TPM_ALG_NULL
        // |           |                      |   NOTE: When both sign and decrypt are SET, restricted shall be CLEAR and scheme shall be TPM_ALG_NULL.
        // | keyBits   | TPMI_RSA_KEY_BITS    | Number of bits in the public modulus
        // | exponent  | UINT32               | The public exponent. Aprime number greater than 2.

        // We do not expect to receive a restricted decryption key at this point.
        var isRestrictedDecryptionKey =
            (objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted
            && (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        if (isRestrictedDecryptionKey)
        {
            rsaDetail = null;
            return false;
        }

        // symmetric
        // 11.1.7 TPMT_SYM_DEF_OBJECT
        // This structure is used when different symmetric block cipher (not XOR) algorithms may be selected.
        // If the Object can be an ordinary parent (not a derivation parent), this must be the first field in the Object's parameter (see 12.2.3.7) field.
        // Table 141 — Definition of TPMT_SYM_DEF_OBJECT Structure
        // | Parameter          | Type                 | Description
        // | algorithm          | +TPMI_ALG_SYM_OBJECT | Selects a symmetric block cipher When used in the parameter area of a parent object, this shall be a supported block cipher and not TPM_ALG_NULL
        // | [algorithm]keyBits | TPMU_SYM_KEY_BITS    | The key size
        // | [algorithm]mode    | TPMU_SYM_MODE        | Default mode. When used in the parameter area of a parent object, this shall be TPM_ALG_CFB.

        if (!TryConsume(ref buffer, 2, out var rawSymmetricAlgorithm))
        {
            rsaDetail = null;
            return false;
        }

        var symmetricAlgorithm = (TpmiAlgSymObject) BinaryPrimitives.ReadUInt16BigEndian(rawSymmetricAlgorithm);
        if (symmetricAlgorithm != TpmiAlgSymObject.TpmAlgNull)
        {
            rsaDetail = null;
            return false;
        }
        // [algorithm]keyBits and [algorithm]mode should be ignored when algorithm is equal to TPM_ALG_NULL

        // scheme
        // 11.2.4.2 TPMT_RSA_SCHEME
        // Table 171 — Definition of {RSA} TPMT_RSA_SCHEME Structure
        // | Parameter       | Type                 | Description
        // | scheme          | +TPMI_ALG_RSA_SCHEME | Scheme selector
        // | [scheme]details | TPMU_ASYM_SCHEME     | Scheme parameters
        // We expect the scheme to be equal to TPM_ALG_NULL
        // As we expect the scheme to be TPM_ALG_NULL, it is necessary to verify that the key is an unrestricted signing key or unrestricted decryption key
        var isUnrestrictedSigningKey =
            (objectAttributes & ObjectAttributes.Restricted) != ObjectAttributes.Restricted
            && (objectAttributes & ObjectAttributes.SignEncrypt) == ObjectAttributes.SignEncrypt;
        var isUnrestrictedDecryptionKey =
            (objectAttributes & ObjectAttributes.Restricted) != ObjectAttributes.Restricted
            && (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        if (!(isUnrestrictedSigningKey || isUnrestrictedDecryptionKey))
        {
            rsaDetail = null;
            return false;
        }

        if (!TryConsume(ref buffer, 2, out var rawScheme))
        {
            rsaDetail = null;
            return false;
        }

        var scheme = (TpmiAlgRsaScheme) BinaryPrimitives.ReadUInt16BigEndian(rawScheme);
        if (scheme != TpmiAlgRsaScheme.TpmAlgNull)
        {
            rsaDetail = null;
            return false;
        }
        //[scheme]details is ignored if the scheme is TPM_ALG_NULL

        // keyBits
        // 11.2.4.6 TPMI_RSA_KEY_BITS
        // Table 175 — Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type
        // | Parameter           | Description
        // | $RSA_KEY_SIZES_BITS | the number of bits in the supported key
        // 5.3 Miscellaneous Types
        // Table 5 — Definition of Types for Documentation Clarity
        // | Type   | Name         | Description
        // | UINT16 | TPM_KEY_BITS | a key size in bits
        if (!TryConsume(ref buffer, 2, out var rawKeyBits))
        {
            rsaDetail = null;
            return false;
        }

        var keyBits = BinaryPrimitives.ReadUInt16BigEndian(rawKeyBits);

        // exponent
        if (!TryConsume(ref buffer, 4, out var rawExponent))
        {
            rsaDetail = null;
            return false;
        }

        var exponent = BinaryPrimitives.ReadUInt32BigEndian(rawExponent);
        // An exponent of zero indicates that the exponent is the default of 2^16 + 1.
        if (exponent is 0)
        {
            exponent = 65537U;
        }

        rsaDetail = new(keyBits, exponent);
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
