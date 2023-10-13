using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     12.2.3.6 TPMS_ECC_PARMS
/// </summary>
public class EccParms : AbstractPublicParms
{
    [SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
    protected EccParms(TpmiEccCurve curveId)
    {
        CurveId = curveId;
    }

    public TpmiEccCurve CurveId { get; }

    public static bool TryParseEccParms(
        ref Span<byte> buffer,
        ObjectAttributes objectAttributes,
        [NotNullWhen(true)] out EccParms? eccDetail)
    {
        // 12.2.3.6 TPMS_ECC_PARMS
        // Table 197 — Definition of {ECC} TPMS_ECC_PARMS Structure
        // | Parameter | Type                 | Description
        // | symmetric | TPMT_SYM_DEF_OBJECT+ | For a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode.
        // |           |                      | If the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        // | scheme    | TPMT_ECC_SCHEME+     | If the sign attribute of the key is SET, then this shall be a valid signing scheme.
        // |           |                      |   NOTE: If the sign parameter in curveID indicates a mandatory scheme, then this field shall have the same value.
        // |           |                      | If the decrypt attribute of the key is SET, then this shall be a valid key exchange scheme or TPM_ALG_NULL.
        // |           |                      | If the key is a Storage Key, then this field shall be TPM_ALG_NULL.
        // | curveID   | TPMI_ECC_CURVE       | ECC curve ID
        // | kdf       | TPMT_KDF_SCHEME+     | An optional key derivation scheme for generating a symmetric key from a Z value.
        // |           |                      | If the kdf parameter associated with curveID is not TPM_ALG_NULL then this is required to be NULL.
        // |           |                      |   NOTE: There are currently no commands where this parameter has effect and, in the reference code, this field needs to be set to TPM_ALG_NULL.

        // We do not expect to receive a restricted decryption key at this point.
        var isRestrictedDecryptionKey =
            (objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted
            && (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        if (isRestrictedDecryptionKey)
        {
            eccDetail = null;
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
            eccDetail = null;
            return false;
        }

        var symmetricAlgorithm = (TpmiAlgSymObject) BinaryPrimitives.ReadUInt16BigEndian(rawSymmetricAlgorithm);
        if (symmetricAlgorithm != TpmiAlgSymObject.TpmAlgNull)
        {
            eccDetail = null;
            return false;
        }
        // [algorithm]keyBits and [algorithm]mode should be ignored when algorithm is equal to TPM_ALG_NULL

        // scheme
        // 11.2.5.6 TPMT_ECC_SCHEME
        // Table 182 — Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure
        // | Parameter       | Type                 | Description
        // | scheme          | +TPMI_ALG_ECC_SCHEME | Scheme selector
        // | [scheme]details | TPMU_ASYM_SCHEME     | Scheme parameters
        // We expect the scheme to be equal to TPM_ALG_NULL
        // As we expect the scheme to be TPM_ALG_NULL, it is necessary to verify that the key is an unrestricted signing key or unrestricted decryption key

        if (!TryConsume(ref buffer, 2, out var rawScheme))
        {
            eccDetail = null;
            return false;
        }

        var scheme = (TpmiAlgEccScheme) BinaryPrimitives.ReadUInt16BigEndian(rawScheme);
        if (scheme != TpmiAlgEccScheme.TpmAlgNull)
        {
            eccDetail = null;
            return false;
        }
        //[scheme]details is ignored if the scheme is TPM_ALG_NULL

        // curveID
        // 11.2.5.5 TPMI_ECC_CURVE
        // Table 181 — Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type
        // | Parameter   | Description
        // | $ECC_CURVES | The list of implemented curves
        if (!TryConsume(ref buffer, 2, out var rawCurveId))
        {
            eccDetail = null;
            return false;
        }

        var curveId = (TpmiEccCurve) BinaryPrimitives.ReadUInt16BigEndian(rawCurveId);
        if (!Enum.IsDefined(curveId))
        {
            eccDetail = null;
            return false;
        }

        // kdf
        // 11.2.3.3 TPMT_KDF_SCHEME
        // Table 166 — Definition of TPMT_KDF_SCHEME Structure
        // | Parameter       | Type            | Description
        // | scheme          | +TPMI_ALG_KDF   | Scheme selector
        // | [scheme]details | TPMU_KDF_SCHEME | Scheme parameters
        if (!TryConsume(ref buffer, 2, out var rawKdfScheme))
        {
            eccDetail = null;
            return false;
        }

        var kdfScheme = (TpmiAlgKdf) BinaryPrimitives.ReadUInt16BigEndian(rawKdfScheme);
        // We do not expect any other kdf.scheme than TPM_ALG_NULL.
        if (kdfScheme != TpmiAlgKdf.TpmAlgNull)
        {
            eccDetail = null;
            return false;
        }

        //[scheme]details is ignored if the scheme is TPM_ALG_NULL
        eccDetail = new(curveId);
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
