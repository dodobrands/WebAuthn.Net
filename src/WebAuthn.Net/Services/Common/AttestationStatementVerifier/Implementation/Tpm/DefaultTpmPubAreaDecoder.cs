using System;
using System.Buffers.Binary;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums.Extensions;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

/// <summary>
///     Default implementation of <see cref="ITpmPubAreaDecoder" />.
/// </summary>
/// <remarks>
///     <para>
///         The decoder parses exactly what WebAuthn needs from a TPMT_PUBLIC (TPM 2.0 Library Part 2: Structures, Version 185, clause 12.2.4, Table 235)
///         and applies the cheap sanity checks the reference implementation performs when a public area is unmarshaled (TPMT_PUBLIC_Unmarshal and its callees),
///         validated (PublicAttributesValidation, SchemeChecks) and loaded (CryptValidateKeys), so that a malformed or crafted pubArea is reported as a failed <see cref="Result{TOk}" />
///         instead of surfacing later as an exception from the .NET cryptographic primitives.
///     </para>
///     <para>
///         Reference implementation: <a href="https://github.com/TrustedComputingGroup/TPM/tree/3b1f0e623f244abe2015df9e3ba86de5c9118524">TrustedComputingGroup/TPM, V184 (commit 3b1f0e6)</a>.
///     </para>
/// </remarks>
public class DefaultTpmPubAreaDecoder : ITpmPubAreaDecoder
{
    // 8.3 TPMA_OBJECT, Table 37: bits 0, 3, 15:12 and 31:20 are reserved and "shall be zero".
    // The reference implementation checks the reserved bits with the mask 0xFFF0F001 (TPMA_OBJECT_Unmarshal, TPM_RC_RESERVED_BITS), i.e. it does NOT reserve bit 3:
    // TpmTypes.h still defines TPMA_OBJECT_fixedFirmware as (1 << 3), a stale leftover of the unpublished revisions 169-177
    // (fixedFirmware moved to bit 8 and was renamed firmwareLimited in revision 178; the define is referenced nowhere else in the reference tree).
    // Every published revision (1.59, 1.83, 184, 185) reserves bit 3, so the mask of the published Table 37 would be 0xFFF0F009.
    // The reference implementation takes precedence here: bit 3 is tolerated.
    // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L329
    // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/tpm_public/TpmTypes.h#L983
    private const uint ReservedObjectAttributeBits = 0xFFF0F001u;

    /// <inheritdoc />
    public virtual Result<PubArea> Decode(Span<byte> publicArea)
    {
        var buffer = publicArea;
        // "publicArea"
        // 12.2.4 TPMT_PUBLIC
        // Table 235 defines the public area structure. The Name of the object is nameAlg concatenated with the digest of this structure using nameAlg.
        // Definition of TPMT_PUBLIC Structure
        // | Parameter        | Type              | Description
        // | type             | TPMI_ALG_PUBLIC   | "Algorithm" associated with this object
        // | nameAlg          | +TPMI_ALG_HASH    | Algorithm used for computing the Name of the object. Note: The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to indicate that the nameAlg may be TPM_ALG_NULL.
        // | objectAttributes | TPMA_OBJECT       | Attributes that, along with "type", determine the manipulations of this object
        // | authPolicy       | TPM2B_DIGEST      | Optional policy for using this key. The policy is computed using the "nameAlg" of the object. Note: This is the Empty Policy if no authorization policy is present.
        // | [type]parameters | TPMU_PUBLIC_PARMS | The algorithm or structure details.
        // | [type]unique     | TPMU_PUBLIC_ID    | The unique identifier of the structure. For an asymmetric key, this would be the public key.
        //
        // Reference unmarshaling: TPMT_PUBLIC_Unmarshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L5158

        // ---------------------------------------
        // "publicArea"."type"
        // 12.2.2 TPMI_ALG_PUBLIC
        // Table 225 — Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type
        // | Values             | Comments
        // | TPM_ALG_RSA        |
        // | TPM_ALG_KEYEDHASH  |
        // | TPM_ALG_ECC        |
        // | TPM_ALG_SYMCIPHER  |
        // | TPM_ALG_MLDSA      |
        // | TPM_ALG_HASH_MLDSA |
        // | TPM_ALG_MLKEM      |
        // | #TPM_RC_TYPE       | response code when a public type is not supported
        // We do not support any algorithms other than RSA and ECC: a WebAuthn credential public key is a COSE RSA or EC2 key, so no other object type can ever match it.
        // 6.3 TPM_ALG_ID
        // Table 8 — Definition of (UINT16) TPM_ALG_ID Constants
        // | Algorithm Name | TCG_ALG Value | Reference       | Comments
        // | TPM_ALG_RSA    | 0x0001        | IETF RFC 8017   | the RSA algorithm
        // | TPM_ALG_ECC    | 0x0023        | ISO/IEC 15946-1 | prime field ECC
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L4864
        if (!TryConsume(ref buffer, 2, out var rawType))
        {
            return Result<PubArea>.Fail();
        }

        var type = (TpmAlgPublic) BinaryPrimitives.ReadUInt16BigEndian(rawType);
        if (!Enum.IsDefined(type))
        {
            return Result<PubArea>.Fail();
        }

        // ---------------------------------------
        // "publicArea"."nameAlg"
        // 9.31 TPMI_ALG_HASH
        // TPMI_ALG_HASH is an interface type of all the hash algorithms implemented on a specific TPM.
        // Table 77 — Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type
        // | Values               | Comments
        // | TPM_ALG_SHA1         |
        // | TPM_ALG_SHA256       |
        // | TPM_ALG_SHA384       |
        // | TPM_ALG_SHA512       |
        // | TPM_ALG_SHA256_192   |
        // | TPM_ALG_SM3_256      |
        // | TPM_ALG_SHA3_256     |
        // | TPM_ALG_SHA3_384     |
        // | TPM_ALG_SHA3_512     |
        // | TPM_ALG_SHAKE256_192 |
        // | TPM_ALG_SHAKE256_256 |
        // | TPM_ALG_SHAKE256_512 |
        // | +TPM_ALG_NULL        |
        // | #TPM_RC_HASH         |
        // The "+" (TPM_ALG_NULL allowed) only applies to TPM2_LoadExternal(), whose inPublic is a TPM2B_PUBLIC+.
        // The templates of TPM2_Create(), TPM2_CreatePrimary() and TPM2_Load() are unmarshaled with TPMI_ALG_HASH_Unmarshal(flag = 0), which rejects TPM_ALG_NULL
        // and unknown identifiers (TPM_RC_HASH), and PublicAttributesValidation() rejects nameAlg == TPM_ALG_NULL (TPM_RC_HASH) as well.
        // A WebAuthn credential key is a created key, and WebAuthn requires the Name in certInfo to be computed "using the nameAlg in the pubArea"
        // (Part 1 v185, Clause 13, Table 9: Name := nameAlg || H_nameAlg(publicArea)), so nameAlg must be a known hash algorithm.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L908
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/command/Object/Object_spt.c#L603
        if (!TryConsume(ref buffer, 2, out var rawNameAlg))
        {
            return Result<PubArea>.Fail();
        }

        var nameAlg = (TpmAlgIdHash) BinaryPrimitives.ReadUInt16BigEndian(rawNameAlg);
        if (!Enum.IsDefined(nameAlg))
        {
            return Result<PubArea>.Fail();
        }

        // ---------------------------------------
        // "publicArea"."objectAttributes"
        // 8.3 TPMA_OBJECT
        // This object attribute structure in Table 37 indicates an object’s use, its authorization types, and its relationship to other objects.
        // The state of the attributes is determined when the object is created and they are never changed by the TPM.
        // Additionally, the setting of these structures is reflected in the integrity value of the private area of an object
        // in order to allow the TPM to detect modifications of the Protected Object when stored off the TPM.
        // Definition of (UINT32) TPMA_OBJECT Bits
        // | Bit   | Name                 | Definition
        // |     0 | Reserved             | shall be zero
        // |     1 | fixedTPM             | SET (1): The hierarchy of the object, as indicated by its Qualified Name, may not change.
        // |       |                      | CLEAR (0): The hierarchy of the object may change as a result of this object or an ancestor key being duplicated for use in another hierarchy.
        // |       |                      |  NOTE: fixedTPM does not indicate that key material resides on a single TPM (see sensitiveDataOrigin).
        // |     2 | stClear              | SET (1): Previously saved contexts of this object may not be loaded after Startup(CLEAR).
        // |       |                      | CLEAR (0): Saved contexts of this object may be used after a Shutdown(STATE) and subsequent Startup().
        // |     3 | Reserved             | shall be zero
        // |     4 | fixedParent          | SET (1): The parent of the object may not change.
        // |       |                      | CLEAR (0): The parent of the object may change as the result of a TPM2_Duplicate() of the object.
        // |     5 | sensitiveDataOrigin  | SET (1): Indicates that, when the object was created with TPM2_Create() or TPM2_CreatePrimary(), the TPM generated all of the sensitive data other than the authValue.
        // |       |                      | CLEAR (0): A portion of the sensitive data, other than the authValue, was provided by the caller.
        // |     6 | userWithAuth         | SET (1): Approval of USER role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session.
        // |       |                      | CLEAR (0): Approval of USER role actions with this object may only be done with a policy session.
        // |     7 | adminWithPolicy      | SET (1): Approval of ADMIN role actions with this object may only be done with a policy session.
        // |       |                      | CLEAR (0): Approval of ADMIN role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session.
        // |     8 | firmwareLimited      | SET (1): The object exists only within a firmware-limited hierarchy.
        // |       |                      | CLEAR (0): The object can exist outside a firmware-limited hierarchy.
        // |     9 | svnLimited           | SET (1): The object exists only within an SVN-limited hierarchy.
        // |       |                      | CLEAR (0): The object can exist outside an SVN-limited hierarchy.
        // |    10 | noDA                 | SET (1): The object is not subject to dictionary attack protections.
        // |       |                      | CLEAR (0): The object is subject to dictionary attack protections.
        // |    11 | encryptedDuplication | SET (1): If the object is duplicated, then symmetricAlg shall not be TPM_ALG_NULL and newParentHandle shall not be TPM_RH_NULL.
        // |       |                      | CLEAR (0): The object may be duplicated without an inner wrapper on the private portion of the object and the new parent may be TPM_RH_NULL.
        // | 15:12 | Reserved             | shall be zero
        // |    16 | restricted           | SET (1): Key usage is restricted to manipulate structures of known format; the parent of this key shall have restricted SET.
        // |       |                      | CLEAR (0): Key usage is not restricted to use on special formats.
        // |    17 | decrypt              | SET (1): The private portion of the key may be used to decrypt.
        // |       |                      | CLEAR (0): The private portion of the key may not be used to decrypt.
        // |       |                      |  NOTE: Version 185 deprecated support for keys with both "sign" and "decrypt"
        // |    18 | sign / encrypt       | SET (1): For a symmetric block cipher key, the private portion of the key may be used to encrypt. For other keys, the private portion of the key may be used to sign.
        // |       |                      | CLEAR (0): The private portion of the key may not be used to "sign" or "encrypt".
        // |       |                      |  NOTE: Version 185 deprecated support for keys with both "sign" and "decrypt"
        // |    19 | x509sign             | SET (1): An asymmetric key that may not be used to sign with TPM2_Sign(), TPM2_SignDigest(), or TPM2_SignSequenceComplete().
        // |       |                      | CLEAR (0): A key that may be used with TPM2_Sign(), TPM2_SignDigest, or TPM2_SignSequenceComplete() if sign is SET.
        // |       |                      |  NOTE: This attribute only has significance if sign is SET.
        // |       |                      |  NOTE: This attribute does not prevent the key from being used with other commands, such as TPM2_Quote().
        // | 31:20 | Reserved             | shall be zero
        if (!TryConsume(ref buffer, 4, out var rawObjectAttributes))
        {
            return Result<PubArea>.Fail();
        }

        var rawAttributes = BinaryPrimitives.ReadUInt32BigEndian(rawObjectAttributes);
        // TPMA_OBJECT_Unmarshal(): "check that no reserved bits are set" -> TPM_RC_RESERVED_BITS (see ReservedObjectAttributeBits for the mask and the bit 3 question).
        if ((rawAttributes & ReservedObjectAttributeBits) != 0)
        {
            return Result<PubArea>.Fail();
        }

        var objectAttributes = (ObjectAttributes) rawAttributes;

        // ---------------------------------------
        // "publicArea"."authPolicy"
        // 10.3.2 TPM2B_DIGEST
        // The Table 90 structure is used for a sized buffer that cannot be larger than the largest digest produced by any hash algorithm implemented on the TPM.
        // As with all sized buffers, the size is checked to see if it is within the prescribed range. If not, the response code is TPM_RC_SIZE.
        // NOTE:
        // For any structure, like the one below, that contains an implied size check, it is implied that TPM_RC_SIZE is a possible response code and the response code will not be listed in the table.
        // Definition of TPM2B_DIGEST Structure
        // | Parameter                      | Type   | Description
        // | size                           | UINT16 | size in octets of the buffer field; may be 0
        // | buffer[size]{:sizeof(TPMU_HA)} | BYTE   | the buffer area that can be no larger than a digest
        // The policy digest itself is not needed for the rest of WebAuthn processing, so its bytes are consumed and skipped, but its size is validated:
        // PublicAttributesValidation(): "If there is an authPolicy, it needs to be the size of the digest produced by the nameAlg of the object" (TPM_RC_SIZE);
        // Part 3 v185, clause 12.3.1 (TPM2_LoadExternal): "The TPM will validate that the authPolicy is either the size of the digest produced by nameAlg or the Empty Buffer".
        // Because nameAlg is restricted to known hash algorithms, this also subsumes the TPM2B_DIGEST_Unmarshal() bound "size <= sizeof(TPMU_HA)" (10.2.1, Table 88).
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L1556
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/command/Object/Object_spt.c#L603
        if (!TryConsume(ref buffer, 2, out var rawAuthPolicySize))
        {
            return Result<PubArea>.Fail();
        }

        var authPolicySize = BinaryPrimitives.ReadUInt16BigEndian(rawAuthPolicySize);
        if (authPolicySize > 0)
        {
            if (!TryGetDigestSize(nameAlg, out var nameAlgDigestSize) || authPolicySize != nameAlgDigestSize)
            {
                return Result<PubArea>.Fail();
            }

            if (!TryConsume(ref buffer, authPolicySize, out _))
            {
                return Result<PubArea>.Fail();
            }
        }

        // ---------------------------------------
        // "publicArea"."[type]parameters"
        var publicParmsResult = DecodePublicParms(ref buffer, type, objectAttributes);
        if (publicParmsResult.HasError)
        {
            return Result<PubArea>.Fail();
        }

        // "publicArea"."[type]unique"
        var uniqueResult = DecodeUnique(ref buffer, type);
        if (uniqueResult.HasError)
        {
            return Result<PubArea>.Fail();
        }

        // 12.2.5 TPM2B_PUBLIC (Table 236): "size=" forces the TPM to check that the unmarshaled TPMT_PUBLIC is exactly "size" bytes long,
        // TPM2B_PUBLIC_Unmarshal() returns TPM_RC_SIZE otherwise; the WebAuthn "pubArea" is that TPMT_PUBLIC, so trailing bytes are rejected.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L5215
        if (buffer.Length > 0)
        {
            return Result<PubArea>.Fail();
        }

        // ---------------------------------------
        // Cross-field checks that need both "parameters" and "unique".
        // CryptValidateKeys() is called for a public-only object load (TPM2_LoadExternal() via ObjectLoad()) and for every created key.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/crypt/CryptUtil.c#L1679
        if (publicParmsResult.Ok is RsaParms rsaParms && uniqueResult.Ok is RsaUnique rsaUnique)
        {
            // CryptValidateKeys():
            //   keySizeInBytes = BITS_TO_BYTES(params->rsaDetail.keyBits);
            //   if((unique->rsa.t.size != keySizeInBytes) || (unique->rsa.t.buffer[0] < 0x80))
            //       return TPM_RCS_KEY + blamePublic;
            // The modulus must be exactly keyBits / 8 octets long with the most significant bit of its first octet SET,
            // i.e. the modulus really has keyBits significant bits and carries no leading zero octets.
            if (rsaUnique.Buffer.Length != rsaParms.KeyBits / 8 || rsaUnique.Buffer[0] < 0x80)
            {
                return Result<PubArea>.Fail();
            }
        }
        else if (publicParmsResult.Ok is EccParms eccParms && uniqueResult.Ok is EccUnique eccUnique)
        {
            // CryptValidateKeys():
            //   keySizeInBytes = BITS_TO_BYTES(CryptEccGetKeySizeForCurve(curveId));
            //   if(unique->ecc.x.t.size != keySizeInBytes || unique->ecc.y.t.size != keySizeInBytes)
            //       return TPM_RCS_KEY + blamePublic;
            // Both coordinates must be exactly the coordinate size of the curve (32/48/66 octets).
            // TPM2B_ECC_PARAMETER_Unmarshal() only bounds the size by MAX_ECC_KEY_BYTES, so this is a post-unmarshal check the decoder has to replicate itself.
            // COSE EC2 keys (RFC 9053, section 7.1.1) and .NET ECParameters use the same fixed-width encoding, so this also guarantees that the comparison
            // with the credential public key compares like with like.
            if (!TryGetCoordinateSize(eccParms.CurveId, out var coordinateSize)
                || eccUnique.X.Length != coordinateSize
                || eccUnique.Y.Length != coordinateSize)
            {
                return Result<PubArea>.Fail();
            }
        }
        else
        {
            // "parameters" and "unique" are both selected by "type" and must belong to the same algorithm.
            return Result<PubArea>.Fail();
        }

        var pubArea = new PubArea(
            type,
            nameAlg,
            objectAttributes,
            publicParmsResult.Ok,
            uniqueResult.Ok);
        return Result<PubArea>.Success(pubArea);
    }

    /// <summary>
    ///     Decodes the TPMU_PUBLIC_PARMS from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPMU_PUBLIC_PARMS.</param>
    /// <param name="type">Type of asymmetric algorithm with a public and private key, used by the TPM module for generating digital signatures in the process of WebAuthn ceremonies.</param>
    /// <param name="objectAttributes">Flags that indicate an object's use, its authorization types, and its relationship to other objects. The state of the attributes is determined when the object is created and they are never changed by the TPM.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AbstractPublicParms" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<AbstractPublicParms> DecodePublicParms(
        ref Span<byte> buffer,
        TpmAlgPublic type,
        ObjectAttributes objectAttributes)
    {
        // "publicArea"."[type]parameters"
        // 12.2.3.9 TPMU_PUBLIC_PARMS
        // Table 233 defines the possible parameter definition structures that may be contained in the public portion of a key.
        // Definition of TPMU_PUBLIC_PARMS Union <IN/OUT>
        // | Parameter        | Type                  | Selector           | Description (1)
        // | keyedHashDetail  | TPMS_KEYEDHASH_PARMS  | TPM_ALG_KEYEDHASH  | "sign | decrypt | neither (2)"
        // | symDetail        | TPMS_SYMCIPHER_PARMS  | TPM_ALG_SYMCIPHER  | "sign | decrypt | neither (2)"
        // | rsaDetail        | TPMS_RSA_PARMS        | TPM_ALG_RSA        | "decrypt + sign (2)"
        // | eccDetail        | TPMS_ECC_PARMS        | TPM_ALG_ECC        | "decrypt + sign (2)"
        // | mldsaDetail      | TPMS_MLDSA_PARMS      | TPM_ALG_MLDSA      | sign
        // | hash_mldsaDetail | TPMS_HASH_MLDSA_PARMS | TPM_ALG_HASH_MLDSA | sign
        // | mlkemDetail      | TPMS_MLKEM_PARMS      | TPM_ALG_MLKEM      | decrypt
        //  NOTE:
        //   [1] The Description column indicates which of TPMA_OBJECT.decrypt or TPMA_OBJECT.sign may be set.
        //   [2] "+" indicates that both may be set but one shall be set. "|" indicates the optional settings.
        //   Support for both sign and decrypt on the same key was deprecated in version 185. See Part 0.

        var canSign = (objectAttributes & ObjectAttributes.SignEncrypt) == ObjectAttributes.SignEncrypt;

        // "decrypt + sign (2)" for "rsaDetail" and "eccDetail": one of them shall be set.
        // PublicAttributesValidation(): "only a data object may have both sign and decrypt CLEAR" (TPM_RC_ATTRIBUTES for any type other than TPM_ALG_KEYEDHASH).
        // Beyond that, a WebAuthn credential key must be able to sign assertions, which a TPM only does with a key whose "sign" attribute is SET:
        // Part 3 v185, clause 20.5.1 (TPM2_Sign): "If the sign attribute is not SET in the key referenced by handle, then the TPM shall return TPM_RC_KEY".
        // A decrypt-only key can therefore never be the credential key and is rejected here (this check subsumes the "neither" case).
        // "decrypt" SET in addition to "sign" is tolerated: Windows Hello creates RSA credential keys with sign | decrypt (restricted CLEAR, scheme TPM_ALG_NULL),
        // the scheme/attribute rules for that combination are applied in DecodeRsaParms() / DecodeEccParms(). "restricted" signing keys are tolerated as well. "x509sign" is not checked.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/command/Object/Object_spt.c#L603
        if (!canSign)
        {
            return Result<AbstractPublicParms>.Fail();
        }

        // Since only RSA and ECC are supported, we expect "rsaDetail" (TPMS_RSA_PARMS) or "eccDetail" (TPMS_ECC_PARMS).
        switch (type)
        {
            case TpmAlgPublic.Rsa:
                {
                    // "publicArea"."[type]parameters"
                    //  => "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail" (TPMS_RSA_PARMS)
                    var rsaResult = DecodeRsaParms(ref buffer, objectAttributes);
                    if (rsaResult.HasError)
                    {
                        return Result<AbstractPublicParms>.Fail();
                    }

                    return Result<AbstractPublicParms>.Success(rsaResult.Ok);
                }
            case TpmAlgPublic.Ecc:
                {
                    // "publicArea"."[type]parameters"
                    //  => "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail" (TPMS_ECC_PARMS)
                    var eccResult = DecodeEccParms(ref buffer, objectAttributes);
                    if (eccResult.HasError)
                    {
                        return Result<AbstractPublicParms>.Fail();
                    }

                    return Result<AbstractPublicParms>.Success(eccResult.Ok);
                }
            default:
                {
                    return Result<AbstractPublicParms>.Fail();
                }
        }
    }

    /// <summary>
    ///     Decodes the TPMS_RSA_PARMS from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPMS_RSA_PARMS.</param>
    /// <param name="objectAttributes">Flags that indicate an object's use, its authorization types, and its relationship to other objects. The state of the attributes is determined when the object is created and they are never changed by the TPM.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="RsaParms" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<RsaParms> DecodeRsaParms(
        ref Span<byte> buffer,
        ObjectAttributes objectAttributes)
    {
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail" (TPMS_RSA_PARMS)
        // 12.2.3.4 TPMS_RSA_PARMS
        // Table 228 defines the TPMS_RSA_PARMS structure.
        // A TPM compatible with this specification and supporting RSA shall support two primes and an exponent of zero.
        // An exponent of zero indicates that the exponent is the default of 2^16 + 1.
        // Support for other values is optional.
        // Use of other exponents in duplicated keys is not recommended because the resulting keys would not be interoperable with other TPMs.
        //  NOTE:
        //   Implementations are not required to check that "exponent" is the default exponent.
        //   They may fail to load or generate the key if "exponent" is not zero.
        // Definition of {RSA} TPMS_RSA_PARMS Structure
        // | Parameter | Type                 | Description
        // | symmetric | TPMT_SYM_DEF_OBJECT+ | For a restricted decryption key, shall be set to a supported symmetric algorithm, key size, and mode.
        // |           |                      | If the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        // | scheme    | TPMT_RSA_SCHEME+     | scheme.scheme shall be:
        // |           |                      | - for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
        // |           |                      | - for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
        // |           |                      | - for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL unless the object also has the "sign" attribute
        // |           |                      | - for a restricted decryption key, TPM_ALG_NULL
        // |           |                      | - when both "sign" and "decrypt" are SET, restricted shall be CLEAR and "scheme" shall be TPM_ALG_NULL.
        // |           |                      |  Deprecated: Support for TPM_ALG_NULL except for Storage Keys, and keys intended for use with the raw RSAEP/RSADP primitive, was deprecated in version 185. See Part 0.
        // | keyBits   | TPMI_RSA_KEY_BITS    | number of bits in the public modulus
        // | exponent  | UINT32               | the public exponent; an odd number greater than 2

        var sign = (objectAttributes & ObjectAttributes.SignEncrypt) == ObjectAttributes.SignEncrypt;
        var decrypt = (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        var restricted = (objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted;

        // We do not expect to receive a restricted decryption key (a Storage Key) at this point.
        // Part 1 v185, clause 22.1.4: "A restricted decryption key is often referred to in this specification as a Storage Key."
        // Such a key must have "sign" CLEAR (8.3.3.14: sign "shall not be SET if decrypt and restricted are both SET";
        // PublicAttributesValidation(): sign == decrypt with restricted SET -> TPM_RC_ATTRIBUTES), so it can never be a WebAuthn credential key.
        if (restricted && decrypt)
        {
            return Result<RsaParms>.Fail();
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."symmetric"
        // 11.1.7 TPMT_SYM_DEF_OBJECT
        // This Table 163 structure is used when different symmetric block cipher (not XOR) algorithms may be selected.
        // Definition of TPMT_SYM_DEF_OBJECT Structure
        // | Parameter          | Type                 | Description
        // | algorithm          | +TPMI_ALG_SYM_OBJECT | Selects a symmetric block cipher
        // |                    |                      | When used in the parameter area of a parent object, this shall be a supported block cipher and not TPM_ALG_NULL
        // | [algorithm]keyBits | TPMU_SYM_KEY_BITS    | The key size
        // | [algorithm]mode    | TPMU_SYM_MODE        | Default mode. When used in the parameter area of a parent object, this shall be TPM_ALG_CFB.
        // | [algorithm]details | TPMU_SYM_DETAILS     | Contains the additional algorithm details, if any
        // SchemeChecks(): "For an asymmetric key that is not a parent, the symmetric algorithms must be TPM_ALG_NULL" (TPM_RC_SYMMETRIC).
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3112

        // TPMI_ALG_SYM_OBJECT is TPM_ALG_ID, TPM_ALG_ID is UINT16
        if (!TryConsume(ref buffer, 2, out var rawSymmetricAlgorithm))
        {
            return Result<RsaParms>.Fail();
        }

        var symmetricAlgorithm = (TpmiAlgSymObject) BinaryPrimitives.ReadUInt16BigEndian(rawSymmetricAlgorithm);
        if (symmetricAlgorithm != TpmiAlgSymObject.TpmAlgNull)
        {
            return Result<RsaParms>.Fail();
        }
        // [algorithm]keyBits
        // [algorithm]mode
        // [algorithm]details
        // should be ignored when algorithm is equal to TPM_ALG_NULL

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."scheme"
        // 11.2.4.3 TPMT_RSA_SCHEME
        // Table 191 — Definition of {RSA} TPMT_RSA_SCHEME Structure
        // | Parameter       | Type                 | Description
        // | scheme          | +TPMI_ALG_RSA_SCHEME | scheme selector
        // | [scheme]details | TPMU_RSA_SCHEME      | scheme parameters

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."scheme"."scheme"
        // 11.2.4.1 TPMI_ALG_RSA_SCHEME
        // Table 189 — Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type
        // | Values         | Comments
        // | TPM_ALG_RSASSA |
        // | TPM_ALG_RSAES  |
        // | TPM_ALG_RSAPSS |
        // | TPM_ALG_OAEP   |
        // | +TPM_ALG_NULL  |
        // | #TPM_RC_VALUE  |
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L4029

        // TPMI_ALG_RSA_SCHEME based on TPM_ALG_ID (UINT16)
        if (!TryConsume(ref buffer, 2, out var rawScheme))
        {
            return Result<RsaParms>.Fail();
        }

        var scheme = (TpmiAlgRsaScheme) BinaryPrimitives.ReadUInt16BigEndian(rawScheme);
        if (!Enum.IsDefined(scheme))
        {
            return Result<RsaParms>.Fail();
        }

        // scheme.scheme shall be:
        // - for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
        // - for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
        // - for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL unless the object also has the "sign" attribute
        // - for a restricted decryption key, TPM_ALG_NULL
        // - when both "sign" and "decrypt" are SET, restricted shall be CLEAR and scheme shall be TPM_ALG_NULL
        //
        // This mirrors SchemeChecks() of the reference implementation:
        // - sign == decrypt -> the scheme must be TPM_ALG_NULL ("there is no way to specify both a sign and a decrypt scheme in the key");
        // - sign only -> a signing scheme (CryptIsAsymSignScheme(TPM_ALG_RSA): TPM_ALG_RSASSA, TPM_ALG_RSAPSS), or TPM_ALG_NULL if the key is not restricted;
        // - decrypt only -> TPM_ALG_NULL, or a decryption scheme (CryptIsAsymDecryptScheme(TPM_ALG_RSA): TPM_ALG_RSAES, TPM_ALG_OAEP) if the key is not restricted.
        // A WebAuthn credential key has "sign" SET (DecodePublicParms()) and is not a restricted decryption key (checked above), so only three cases are reachable:
        // sign + decrypt (restricted CLEAR, scheme TPM_ALG_NULL), restricted signing key (TPM_ALG_RSAPSS / TPM_ALG_RSASSA) and unrestricted signing key (TPM_ALG_RSAPSS / TPM_ALG_RSASSA / TPM_ALG_NULL).
        // A decrypt-only key cannot sign and is rejected.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/command/Object/Object_spt.c#L406
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/crypt/CryptUtil.c#L1248
        if (sign && decrypt)
        {
            // when both "sign" and "decrypt" are SET, restricted shall be CLEAR and "scheme" shall be TPM_ALG_NULL
            if (restricted || scheme != TpmiAlgRsaScheme.TpmAlgNull)
            {
                return Result<RsaParms>.Fail();
            }
        }
        else if (sign)
        {
            if (restricted)
            {
                // for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
                if (scheme != TpmiAlgRsaScheme.TpmAlgRsapss && scheme != TpmiAlgRsaScheme.TpmAlgRsassa)
                {
                    return Result<RsaParms>.Fail();
                }
            }
            else
            {
                // for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
                if (scheme != TpmiAlgRsaScheme.TpmAlgRsapss && scheme != TpmiAlgRsaScheme.TpmAlgRsassa && scheme != TpmiAlgRsaScheme.TpmAlgNull)
                {
                    return Result<RsaParms>.Fail();
                }
            }
        }
        else
        {
            // a decryption key (or a key with neither attribute) can never be a WebAuthn credential key
            return Result<RsaParms>.Fail();
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."scheme"."[scheme]details"
        // 11.2.4.2 TPMU_RSA_SCHEME
        // Table 190 — Definition of {RSA} TPMU_RSA_SCHEME Union
        // | Parameter | Type             | Selector       | Description
        // | rsassa    | TPMS_SCHEME_HASH | TPM_ALG_RSASSA |
        // | rsaes     | TPMS_EMPTY       | TPM_ALG_RSAES  |
        // | rsapss    | TPMS_SCHEME_HASH | TPM_ALG_RSAPSS |
        // | oaep      | TPMS_SCHEME_HASH | TPM_ALG_OAEP   |
        // | null      |                  | TPM_ALG_NULL   | unpadded RSA
        // (Earlier specification versions defined this union as TPMU_ASYM_SCHEME, shared by RSA and ECC; the V184 reference implementation still marshals through TPMU_ASYM_SCHEME_Marshal.)

        // Common TPMU_ASYM_SCHEME marshal reference logic
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3938

        // TPM_ALG_RSASSA => TPMS_SIG_SCHEME_RSASSA_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1202
        // TPMS_SIG_SCHEME_RSASSA_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_RSAES => TPMS_ENC_SCHEME_RSAES_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1302
        // TPMS_ENC_SCHEME_RSAES_Marshal => TPMS_EMPTY_Marshal

        // TPM_ALG_RSAPSS => TPMS_SIG_SCHEME_RSAPSS_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1212
        // TPMS_SIG_SCHEME_RSAPSS_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_OAEP => TPMS_ENC_SCHEME_OAEP_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1312
        // TPMS_ENC_SCHEME_OAEP_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_NULL => No-op, not marshaled

        // ---
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3361
        // TPMS_SCHEME_HASH_Marshal => TPMI_ALG_HASH_Marshal

        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L1335
        // TPMS_EMPTY_Marshal => No-op, not marshaled.

        // ---
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L576
        // TPM_INLINE UINT16 TPMI_ALG_HASH_Marshal(
        // TPMI_ALG_HASH* source, BYTE** buffer, INT32* size)
        // {
        //     return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
        // }
        //
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L156
        // TPM_INLINE UINT16 TPM_ALG_ID_Marshal(TPM_ALG_ID* source, BYTE** buffer, INT32* size)
        // {
        //     return UINT16_Marshal((UINT16*)(source), (buffer), (size));
        // }
        // TPM_ALG_OAEP (TPMS_SCHEME_HASH) and TPM_ALG_RSAES (TPMS_EMPTY) cannot reach this point: they are decryption schemes, rejected above for a key with "sign" SET.
        if (scheme == TpmiAlgRsaScheme.TpmAlgRsassa
            || scheme == TpmiAlgRsaScheme.TpmAlgRsapss)
        {
            // 11.1.17 TPMS_SCHEME_HASH
            // Table 173 — Definition of TPMS_SCHEME_HASH Structure
            // | Parameter | Type          | Description
            // | hashAlg   | TPMI_ALG_HASH | the hash algorithm used to digest the message
            // TPMS_SCHEME_HASH_Unmarshal() -> TPMI_ALG_HASH_Unmarshal(flag = 0): TPM_ALG_NULL and unknown identifiers -> TPM_RC_HASH;
            // SchemeChecks(): a signing scheme with hashAlg == TPM_ALG_NULL -> TPM_RC_SCHEME.
            // The value itself is not needed for WebAuthn (the assertion signature algorithm comes from the COSE credential public key), it is only validated.
            // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3353
            if (!TryConsume(ref buffer, 2, out var rawSchemeHashAlg))
            {
                return Result<RsaParms>.Fail();
            }

            var schemeHashAlg = (TpmAlgIdHash) BinaryPrimitives.ReadUInt16BigEndian(rawSchemeHashAlg);
            if (!Enum.IsDefined(schemeHashAlg))
            {
                return Result<RsaParms>.Fail();
            }
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."keyBits"
        // 11.2.4.7 TPMI_RSA_KEY_BITS
        // This Table 195 holds the value that is the maximum size allowed for an RSA key.
        // NOTE:
        //  An implementation is allowed to provide limited support for smaller RSA key sizes.
        //  That is, a TPM may be able to accept a smaller RSA key size in TPM2_LoadExternal()
        //  when only the public area is loaded but not accept that smaller key size in any command
        //  that loads both the public and private portions of an RSA key.
        //  This would allow the TPM to validate signatures using the smaller key but would prevent
        //  the TPM from using the smaller key size for any other purpose.
        // Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type
        // | Parameter           | Description
        // | $RSA_KEY_SIZES_BITS | The number of bits in the supported key
        // | #TPM_RC_VALUE       | error when key size is not supported
        // 5.3 Miscellaneous Types
        // Table 5 defines types either for compatibility with previous versions of this specification or for clarity of this specification.
        // Definition of Types for Documentation Clarity
        // | Type   | Name         | Description
        // | UINT16 | TPM_KEY_BITS | A key size in bits
        //
        // TPMI_RSA_KEY_BITS_Unmarshal() accepts only the compiled-in set $RSA_KEY_SIZES_BITS (TPM_RC_VALUE otherwise); in the reference profile (TpmProfile_Common.h) these are 1024, 2048, 3072 and 4096 (16384 is disabled).
        // The supported set is implementation-defined, so the decoder stays tolerant: a non-zero whole number of octets within the range the specification enumerates (up to 16384 bits).
        // The length of the modulus is checked against keyBits in Decode() once "unique" has been decoded.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L4180
        if (!TryConsume(ref buffer, 2, out var rawKeyBits))
        {
            return Result<RsaParms>.Fail();
        }

        var keyBits = BinaryPrimitives.ReadUInt16BigEndian(rawKeyBits);
        if (keyBits == 0 || keyBits % 8 != 0 || keyBits > 16384)
        {
            return Result<RsaParms>.Fail();
        }

        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."exponent"
        if (!TryConsume(ref buffer, 4, out var rawExponent))
        {
            return Result<RsaParms>.Fail();
        }

        var exponent = BinaryPrimitives.ReadUInt32BigEndian(rawExponent);
        // Table 228: "the public exponent; an odd number greater than 2".
        // CryptValidateKeys(): "if(params->rsaDetail.exponent != 0 && params->rsaDetail.exponent < 7) return TPM_RCS_VALUE" (0 means the default exponent).
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/crypt/CryptUtil.c#L1679
        if (exponent != 0 && (exponent < 7 || (exponent & 1) == 0))
        {
            return Result<RsaParms>.Fail();
        }

        // An exponent of zero indicates that the exponent is the default of 2^16 + 1 (RSA_DEFAULT_PUBLIC_EXPONENT in the reference implementation).
        if (exponent is 0)
        {
            exponent = 65537U;
        }

        var rsaDetail = new RsaParms(keyBits, exponent);
        return Result<RsaParms>.Success(rsaDetail);
    }

    /// <summary>
    ///     Decodes the TPMS_ECC_PARMS from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPMS_ECC_PARMS.</param>
    /// <param name="objectAttributes">Flags that indicate an object's use, its authorization types, and its relationship to other objects. The state of the attributes is determined when the object is created and they are never changed by the TPM.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="EccParms" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<EccParms> DecodeEccParms(
        ref Span<byte> buffer,
        ObjectAttributes objectAttributes)
    {
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail" (TPMS_ECC_PARMS)
        // 12.2.3.5 TPMS_ECC_PARMS
        // This Table 229 structure contains the parameters for prime modulus ECC.
        // Definition of {ECC} TPMS_ECC_PARMS Structure
        // | Parameter | Type                 | Description
        // | symmetric | TPMT_SYM_DEF_OBJECT+ | For a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode.
        // |           |                      | If the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        // |           |                      | The TPM will return TPM_RC_SYMMETRIC if any of the above requirements are not met.
        // | scheme    | TPMT_ECC_SCHEME+     | If the sign attribute of the key is SET, then this shall be a valid signing scheme.
        // |           |                      | If the sign parameter in curveID indicates a mandatory scheme, then this field shall have the same value.
        // |           |                      | If the decrypt attribute of the key is SET, then this shall be a valid key exchange scheme or TPM_ALG_NULL.
        // |           |                      | If the key is a Storage Key, then this field shall be TPM_ALG_NULL.
        // |           |                      | If the key is not a Storage Key, and curveID is either TPM_ECC_CURVE_25519 or TPM_ECC_CURVE_448, then this field shall not be TPM_ALG_NULL.
        // |           |                      | The TPM will return TPM_RC_SCHEME if any of the above requirements are not met.
        // |           |                      |  Deprecated: Support for TPM_ALG_NULL except for Storage Keys was deprecated in version 185. See Part 0.
        // | curveID   | TPMI_ECC_CURVE       | ECC curve ID
        // | kdf       | TPMT_KDF_SCHEME+     | if the key is an unrestricted decryption TPM_ALG_ECDH key, an optional key derivation scheme
        // |           |                      | Shall be NULL in all other cases (TPM_RC_KDF).
        // |           |                      | If this field is not NULL, then this key can be used with TPM2_Encapsulate() and TPM2_Decapsulate() (as well as TPM2_ECDH_KeyGen() and TPM2_ECDH_ZGen()).
        // |           |                      | In the context of TPM2_Encapsulate() and TPM2_Decapsulate(), the KEM is equivalent to DHKEM(curveID, kdf) from RFC 9180
        // |           |                      |  NOTE: Currently, TPM_ALG_HKDF is the only supported KDF for DHKEM.

        var sign = (objectAttributes & ObjectAttributes.SignEncrypt) == ObjectAttributes.SignEncrypt;
        var decrypt = (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        var restricted = (objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted;

        // We do not expect to receive a restricted decryption key (a Storage Key) at this point.
        // Part 1 v185, clause 22.1.4: "A restricted decryption key is often referred to in this specification as a Storage Key."
        // Such a key must have "sign" CLEAR (8.3.3.14: sign "shall not be SET if decrypt and restricted are both SET";
        // PublicAttributesValidation(): sign == decrypt with restricted SET -> TPM_RC_ATTRIBUTES), so it can never be a WebAuthn credential key.
        if (restricted && decrypt)
        {
            return Result<EccParms>.Fail();
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."symmetric"
        // 11.1.7 TPMT_SYM_DEF_OBJECT
        // This Table 163 structure is used when different symmetric block cipher (not XOR) algorithms may be selected.
        // Definition of TPMT_SYM_DEF_OBJECT Structure
        // | Parameter          | Type                 | Description
        // | algorithm          | +TPMI_ALG_SYM_OBJECT | Selects a symmetric block cipher
        // |                    |                      | When used in the parameter area of a parent object, this shall be a supported block cipher and not TPM_ALG_NULL
        // | [algorithm]keyBits | TPMU_SYM_KEY_BITS    | The key size
        // | [algorithm]mode    | TPMU_SYM_MODE        | Default mode. When used in the parameter area of a parent object, this shall be TPM_ALG_CFB.
        // | [algorithm]details | TPMU_SYM_DETAILS     | Contains the additional algorithm details, if any
        // SchemeChecks(): "For an asymmetric key that is not a parent, the symmetric algorithms must be TPM_ALG_NULL" (TPM_RC_SYMMETRIC).
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3112

        // TPMI_ALG_SYM_OBJECT is TPM_ALG_ID, TPM_ALG_ID is UINT16
        if (!TryConsume(ref buffer, 2, out var rawSymmetricAlgorithm))
        {
            return Result<EccParms>.Fail();
        }

        var symmetricAlgorithm = (TpmiAlgSymObject) BinaryPrimitives.ReadUInt16BigEndian(rawSymmetricAlgorithm);
        if (symmetricAlgorithm != TpmiAlgSymObject.TpmAlgNull)
        {
            return Result<EccParms>.Fail();
        }
        // [algorithm]keyBits
        // [algorithm]mode
        // [algorithm]details
        // should be ignored when algorithm is equal to TPM_ALG_NULL

        // ------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."scheme"
        // 11.2.5.7 TPMT_ECC_SCHEME
        // Table 203 — Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure
        // | Parameter       | Type                 | Description
        // | scheme          | +TPMI_ALG_ECC_SCHEME | scheme selector
        // | [scheme]details | TPMU_ECC_SCHEME      | scheme parameters

        // ------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."scheme"."scheme"
        // 11.2.5.4 TPMI_ALG_ECC_SCHEME
        // Table 200 — Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type
        // | Values             | Comments
        // | TPM_ALG_ECDSA      |
        // | TPM_ALG_ECDAA      |
        // | TPM_ALG_SM2        |
        // | TPM_ALG_ECSCHNORR  |
        // | TPM_ALG_EDDSA      |
        // | TPM_ALG_HASH_EDDSA |
        // | TPM_ALG_ECDH       |
        // | TPM_ALG_SM2        |
        // | TPM_ALG_ECMQV      |
        // | +TPM_ALG_NULL      |
        // | #TPM_RC_SCHEME     |

        // 6.3 TPM_ALG_ID, Table 8:
        // TPM_ALG_NULL       0x0010 - null algorithm
        // TPM_ALG_ECDSA      0x0018 - signature algorithm using elliptic curve cryptography (ECC) (Non-deterministic ECDSA)
        // TPM_ALG_ECDH       0x0019 - Elliptic Curve Diffie-Hellman
        // TPM_ALG_ECDAA      0x001A - elliptic-curve based, anonymous signing scheme
        // TPM_ALG_SM2        0x001B - SM2 - depending on context, either an elliptic-curve based signature algorithm, an encryption scheme or a key exchange protocol
        // TPM_ALG_ECSCHNORR  0x001C - elliptic-curve based Schnorr signature
        // TPM_ALG_ECMQV      0x001D - "Full MQV, C(2e, 2s, ECC MQV)" defined in 6.1.1.4 of SP 800-56A
        // TPM_ALG_EDDSA      0x0060 - Edwards-curve Digital Signature Algorithm (PureEdDSA)
        // TPM_ALG_HASH_EDDSA 0x0061 - Edwards-curve Digital Signature Algorithm (HashEdDSA). Note: Earlier TCG specifications used the name TPM_ALG_EDDSA_PH.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L4350

        // TPMI_ALG_ECC_SCHEME based on TPM_ALG_ID (UINT16)
        if (!TryConsume(ref buffer, 2, out var rawScheme))
        {
            return Result<EccParms>.Fail();
        }

        var scheme = (TpmiAlgEccScheme) BinaryPrimitives.ReadUInt16BigEndian(rawScheme);
        if (!Enum.IsDefined(scheme))
        {
            return Result<EccParms>.Fail();
        }

        // Scheme/attribute rules, a mirror of SchemeChecks() of the reference implementation for TPM_ALG_ECC:
        // - CryptIsAsymSignScheme(TPM_ALG_ECC): TPM_ALG_ECDSA, TPM_ALG_ECDAA, TPM_ALG_ECSCHNORR, TPM_ALG_SM2;
        // - CryptIsAsymDecryptScheme(TPM_ALG_ECC): TPM_ALG_ECDH, TPM_ALG_SM2, TPM_ALG_ECMQV;
        // - sign == decrypt -> the scheme must be TPM_ALG_NULL; sign only -> a signing scheme, or TPM_ALG_NULL if the key is not restricted;
        //   decrypt only -> TPM_ALG_NULL, or a key exchange scheme if the key is not restricted;
        // - PublicAttributesValidation(): sign == decrypt with restricted SET -> TPM_RC_ATTRIBUTES.
        // TPM_ALG_EDDSA and TPM_ALG_HASH_EDDSA are in neither set (ALG_EDDSA is disabled in the reference profile) and are only defined for the Edwards curves
        // (TPM_ECC_CURVE_25519, TPM_ECC_CURVE_448), which are not supported by this library, so they are rejected outright.
        // Their [scheme]details also differ between the specification versions (TPMS_EMPTY in v185 Table 202, TPMS_SCHEME_HASH in the V184 reference implementation), which does not matter once they are refused.
        // The curve-mandated signing scheme (CryptGetCurveSignScheme(), the "sign" field of TPMS_ALGORITHM_DETAIL_ECC, Table 204) is TPM_ALG_NULL for every NIST curve, so no curve/scheme pairing check is needed.
        // Since a WebAuthn credential key has "sign" SET (DecodePublicParms()), the decrypt-only cases of this matrix (TPM_ALG_ECDH, TPM_ALG_ECMQV, TPM_ALG_SM2 key exchange) always end up rejected; the matrix is kept faithful anyway.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/command/Object/Object_spt.c#L406
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/crypt/CryptUtil.c#L1248
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/crypt/CryptUtil.c#L1361
        switch (scheme)
        {
            case TpmiAlgEccScheme.TpmAlgNull:
                {
                    // a restricted signing key must name its signing scheme
                    if (sign && !decrypt && restricted)
                    {
                        return Result<EccParms>.Fail();
                    }

                    break;
                }
            case TpmiAlgEccScheme.TpmAlgEcdsa:
            case TpmiAlgEccScheme.TpmAlgEcdaa:
            case TpmiAlgEccScheme.TpmAlgEcschnorr:
                {
                    // signing schemes: "sign" SET and "decrypt" CLEAR
                    if (!sign || decrypt)
                    {
                        return Result<EccParms>.Fail();
                    }

                    break;
                }
            case TpmiAlgEccScheme.TpmAlgSm2:
                {
                    // both a signing and a key exchange scheme: exactly one of "sign" / "decrypt"
                    if (sign == decrypt)
                    {
                        return Result<EccParms>.Fail();
                    }

                    break;
                }
            case TpmiAlgEccScheme.TpmAlgEcdh:
            case TpmiAlgEccScheme.TpmAlgEcmqv:
                {
                    // key exchange schemes: "decrypt" SET and "sign" CLEAR
                    if (!decrypt || sign)
                    {
                        return Result<EccParms>.Fail();
                    }

                    break;
                }
            case TpmiAlgEccScheme.TpmAlgEddsa:
            case TpmiAlgEccScheme.TpmAlgHashEddsa:
            default:
                {
                    return Result<EccParms>.Fail();
                }
        }

        // when both "sign" and "decrypt" are SET, restricted shall be CLEAR and "scheme" shall be TPM_ALG_NULL
        if (sign && decrypt && (restricted || scheme != TpmiAlgEccScheme.TpmAlgNull))
        {
            return Result<EccParms>.Fail();
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."scheme"."[scheme]details"
        // 11.2.5.6 TPMU_ECC_SCHEME
        // Table 202 — Definition of {ECC} TPMU_ECC_SCHEME Union
        // | Parameter  | Type              | Selector           | Description
        // | ecdsa      | TPMS_SCHEME_HASH  | TPM_ALG_ECDSA      |
        // | ecschnorr  | TPMS_SCHEME_HASH  | TPM_ALG_ECSCHNORR  |
        // | eddsa      | TPMS_EMPTY        | TPM_ALG_EDDSA      |
        // | hash_eddsa | TPMS_EMPTY        | TPM_ALG_HASH_EDDSA |
        // | ecdaa      | TPMS_SCHEME_ECDAA | TPM_ALG_ECDAA      |
        // 11.2.2.3 ECC Key Exchange Schemes
        // Table 185 — Definition of Types for {ECC} ECC Key Exchange
        // | Type             | Name
        // | TPMS_SCHEME_HASH | TPMS_KEY_SCHEME_ECDH
        // | TPMS_SCHEME_HASH | TPMS_KEY_SCHEME_SM2
        // | TPMS_SCHEME_HASH | TPMS_KEY_SCHEME_ECMQV
        // (Earlier specification versions defined this union as TPMU_ASYM_SCHEME, shared by RSA and ECC; the V184 reference implementation still marshals through TPMU_ASYM_SCHEME_Marshal
        // and marshals TPM_ALG_EDDSA / TPM_ALG_EDDSA_PH details as TPMS_SCHEME_HASH, unlike the TPMS_EMPTY of v185 Table 202.)

        // Common TPMU_ASYM_SCHEME marshal reference logic
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3938

        // TPM_ALG_ECDSA => TPMS_SIG_SCHEME_ECDSA_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1224
        // TPMS_SIG_SCHEME_ECDSA_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_ECDH => TPMS_KEY_SCHEME_ECDH_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1324
        // TPMS_KEY_SCHEME_ECDH_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_ECDAA => TPMS_SIG_SCHEME_ECDAA_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1235
        // TPMS_SIG_SCHEME_ECDAA_Marshal => TPMS_SCHEME_ECDAA_Marshal

        // TPM_ALG_SM2 => TPMS_KEY_SCHEME_SM2_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1334
        // TPMS_KEY_SCHEME_SM2_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_ECSCHNORR => TPMS_SIG_SCHEME_ECSCHNORR_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1255
        // TPMS_SIG_SCHEME_ECSCHNORR_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_ECMQV => TPMS_KEY_SCHEME_ECMQV_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1344
        // TPMS_KEY_SCHEME_ECMQV_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_EDDSA => TPMS_SIG_SCHEME_EDDSA_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1265
        // TPMS_SIG_SCHEME_EDDSA_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_EDDSA_PH => TPMS_SIG_SCHEME_EDDSA_PH_Marshal
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L1275
        // TPMS_SIG_SCHEME_EDDSA_PH_Marshal => TPMS_SCHEME_HASH_Marshal

        // TPM_ALG_NULL => No-op, not marshaled

        // ---
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3361
        // TPMS_SCHEME_HASH_Marshal => TPMI_ALG_HASH_Marshal
        // ---
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3392
        // UINT16
        // TPMS_SCHEME_ECDAA_Marshal(TPMS_SCHEME_ECDAA* source, BYTE** buffer, INT32* size)
        // {
        //     UINT16 result = 0;
        //     result        = (UINT16)(result
        //                              + TPMI_ALG_HASH_Marshal(
        //                                  (TPMI_ALG_HASH*)&(source->hashAlg), buffer, size));
        //     result =
        //         (UINT16)(result + UINT16_Marshal((UINT16*)&(source->count), buffer, size));
        //     return result;
        // }
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L576
        // TPM_INLINE UINT16 TPMI_ALG_HASH_Marshal(
        // TPMI_ALG_HASH* source, BYTE** buffer, INT32* size)
        // {
        //     return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
        // }
        //
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/include/private/prototypes/Marshal_fp.h#L156
        // TPM_INLINE UINT16 TPM_ALG_ID_Marshal(TPM_ALG_ID* source, BYTE** buffer, INT32* size)
        // {
        //     return UINT16_Marshal((UINT16*)(source), (buffer), (size));
        // }

        // TPM_ALG_EDDSA and TPM_ALG_HASH_EDDSA never reach this point (rejected above).
        if (scheme is TpmiAlgEccScheme.TpmAlgEcdsa
            or TpmiAlgEccScheme.TpmAlgEcdaa
            or TpmiAlgEccScheme.TpmAlgSm2
            or TpmiAlgEccScheme.TpmAlgEcschnorr
            or TpmiAlgEccScheme.TpmAlgEcdh
            or TpmiAlgEccScheme.TpmAlgEcmqv)
        {
            // 11.1.17 TPMS_SCHEME_HASH (Table 173) / 11.1.18 TPMS_SCHEME_ECDAA (Table 174)
            // | Parameter | Type          | Description
            // | hashAlg   | TPMI_ALG_HASH | the hash algorithm used to digest the message
            // TPMS_SCHEME_HASH_Unmarshal() / TPMS_SCHEME_ECDAA_Unmarshal() -> TPMI_ALG_HASH_Unmarshal(flag = 0): TPM_ALG_NULL and unknown identifiers -> TPM_RC_HASH;
            // SchemeChecks(): a signing scheme with hashAlg == TPM_ALG_NULL -> TPM_RC_SCHEME.
            // The value itself is not needed for WebAuthn (the assertion signature algorithm comes from the COSE credential public key), it is only validated.
            // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3353
            // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3382
            if (!TryConsume(ref buffer, 2, out var rawSchemeHashAlg))
            {
                return Result<EccParms>.Fail();
            }

            var schemeHashAlg = (TpmAlgIdHash) BinaryPrimitives.ReadUInt16BigEndian(rawSchemeHashAlg);
            if (!Enum.IsDefined(schemeHashAlg))
            {
                return Result<EccParms>.Fail();
            }
        }

        if (scheme is TpmiAlgEccScheme.TpmAlgEcdaa)
        {
            // 11.1.18 TPMS_SCHEME_ECDAA (Table 174)
            // | Parameter | Type   | Description
            // | count     | UINT16 | the counter value that is used between TPM2_Commit() and the sign operation
            // consume count
            if (!TryConsume(ref buffer, 2, out _))
            {
                return Result<EccParms>.Fail();
            }
        }

        // ------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."curveID"
        // 11.2.5.5 TPMI_ECC_CURVE
        // Table 201 — Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type
        // | Parameter     | Description
        // | $ECC_CURVES   | the list of implemented curves
        // | +TPM_ECC_NONE |
        // | #TPM_RC_CURVE | error when curve is not supported

        // 6.4 TPM_ECC_CURVE
        // The TCG maintains a registry of all curves that have an assigned curve identifier.
        // That registry is the definitive list of curves that may be supported by a TPM.
        // Table 9 — Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT>
        // | Name                | Value  | Comments
        // | TPM_ECC_NONE        | 0x0000 |
        // | TPM_ECC_NIST_P192   | 0x0001 |
        // | TPM_ECC_NIST_P224   | 0x0002 |
        // | TPM_ECC_NIST_P256   | 0x0003 |
        // | TPM_ECC_NIST_P384   | 0x0004 |
        // | TPM_ECC_NIST_P521   | 0x0005 |
        // | TPM_ECC_BN_P256     | 0x0010 | curve to support ECDAA
        // | TPM_ECC_BN_P638     | 0x0011 | curve to support ECDAA
        // | TPM_ECC_SM2_P256    | 0x0020 |
        // | TPM_ECC_BP_P256_R1  | 0x0030 | Brainpool
        // | TPM_ECC_BP_P384_R1  | 0x0031 | Brainpool
        // | TPM_ECC_BP_P512_R1  | 0x0032 | Brainpool
        // | TPM_ECC_CURVE_25519 | 0x0040 | curve to support EdDSA
        // | TPM_ECC_CURVE_448   | 0x0041 | curve to support EdDSA
        // The curveID of a created key is unmarshaled with TPMI_ECC_CURVE_Unmarshal(flag = 0), which rejects TPM_ECC_NONE and every curve the implementation does not support (TPM_RC_CURVE).
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L4394

        if (!TryConsume(ref buffer, 2, out var rawCurveId))
        {
            return Result<EccParms>.Fail();
        }

        var curveId = (TpmiEccCurve) BinaryPrimitives.ReadUInt16BigEndian(rawCurveId);

        // We currently support only:
        // TPM_ECC_NIST_P256
        // TPM_ECC_NIST_P384
        // TPM_ECC_NIST_P521
        // These are exactly the COSE EC2 curves a credential public key can use in this library, so a key on any other curve could never match the attested credential data.
        if (!Enum.IsDefined(curveId))
        {
            return Result<EccParms>.Fail();
        }

        // ------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."kdf"
        // 11.2.3.3 TPMT_KDF_SCHEME
        // Table 188 — Definition of TPMT_KDF_SCHEME Structure
        // | Parameter       | Type            | Description
        // | scheme          | +TPMI_ALG_KDF   | scheme selector
        // | [scheme]details | TPMU_KDF_SCHEME | scheme parameters
        // 9.36 TPMI_ALG_KDF
        // Table 82 — Definition of (TPM_ALG_ID) TPMI_ALG_KDF Type: TPM_ALG_MGF1, TPM_ALG_KDF2, TPM_ALG_KDF1_SP800_56A, TPM_ALG_KDF1_SP800_108, TPM_ALG_HKDF, +TPM_ALG_NULL, #TPM_RC_KDF
        // 11.2.3.2 TPMU_KDF_SCHEME
        // Table 187 — Definition of TPMU_KDF_SCHEME Union
        // | Parameter      | Type                           | Selector
        // | mgf1           | TPMS_KDF_SCHEME_MGF1           | TPM_ALG_MGF1
        // | kdf2           | TPMS_KDF_SCHEME_KDF2           | TPM_ALG_KDF2
        // | kdf1_sp800_56a | TPMS_KDF_SCHEME_KDF1_SP800_56A | TPM_ALG_KDF1_SP800_56A
        // | kdf1_sp800_108 | TPMS_KDF_SCHEME_KDF1_SP800_108 | TPM_ALG_KDF1_SP800_108
        // | hkdf           | TPMS_KDF_SCHEME_HKDF           | TPM_ALG_HKDF
        // | null           |                                | TPM_ALG_NULL
        // Every TPMS_KDF_SCHEME_* is a TPMS_SCHEME_HASH (Table 186), i.e. a non-NULL kdf would be followed by a 2-byte hashAlg (TPM_ALG_HKDF is new in v185 and absent from the V184 reference implementation).
        //
        // SchemeChecks(): "For now, the KDF must be TPM_ALG_NULL" (TPM_RC_KDF).
        // Table 229 allows a non-NULL kdf only for "an unrestricted decryption TPM_ALG_ECDH key" (DHKEM) and requires NULL "in all other cases (TPM_RC_KDF)";
        // such a key can never be a WebAuthn credential key, so only TPM_ALG_NULL (which has no details) is accepted here.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L1086
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/command/Object/Object_spt.c#L406

        if (!TryConsume(ref buffer, 2, out var rawKdfScheme))
        {
            return Result<EccParms>.Fail();
        }

        var kdfScheme = (TpmiAlgKdf) BinaryPrimitives.ReadUInt16BigEndian(rawKdfScheme);
        if (kdfScheme != TpmiAlgKdf.TpmAlgNull)
        {
            return Result<EccParms>.Fail();
        }

        var eccDetail = new EccParms(curveId);
        return Result<EccParms>.Success(eccDetail);
    }

    /// <summary>
    /// Decodes the TPMU_PUBLIC_ID from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPMU_PUBLIC_ID.</param>
    /// <param name="type">Type of asymmetric algorithm with a public and private key, used by the TPM module for generating digital signatures in the process of WebAuthn ceremonies.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AbstractUnique" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<AbstractUnique> DecodeUnique(
        ref Span<byte> buffer,
        TpmAlgPublic type)
    {
        // 12.2.3.2 TPMU_PUBLIC_ID
        // This Table 226 is the union of all values allowed in in the unique field of a TPMT_PUBLIC.
        // NOTE:
        //  The derive member cannot be unmarshaled in a TPMU_PUBLIC_ID.
        //  It is placed in this structure so that the maximum size of a TPM2B_TEMPLATE will be computed correctly.
        // Definition of TPMU_PUBLIC_ID Union <IN/OUT>
        // | Parameter | Type                   | Selector                              | Description
        // | keyedHash | TPM2B_DIGEST           | TPM_ALG_KEYEDHASH                     |
        // | sym       | TPM2B_DIGEST           | TPM_ALG_SYMCIPHER                     |
        // | rsa       | TPM2B_PUBLIC_KEY_RSA   | TPM_ALG_RSA                           |
        // | ecc       | TPMS_ECC_POINT         | TPM_ALG_ECC                           |
        // | mldsa     | TPM2B_PUBLIC_KEY_MLDSA | TPM_ALG_MLDSA or TPM_ALG_HASH_MLDSA   |
        // | mlkem     | TPM2B_PUBLIC_KEY_MLKEM | TPM_ALG_MLKEM                         |
        // | derive    | TPMS_DERIVE            |                                       | only allowed for TPM2_CreateLoaded() when parentHandle is a Derivation Parent.
        switch (type)
        {
            case TpmAlgPublic.Rsa:
                {
                    var rsaResult = DecodeRsaUnique(ref buffer);
                    if (rsaResult.HasError)
                    {
                        return Result<AbstractUnique>.Fail();
                    }

                    return Result<AbstractUnique>.Success(rsaResult.Ok);
                }
            case TpmAlgPublic.Ecc:
                {
                    var eccResult = DecodeEccUnique(ref buffer);
                    if (eccResult.HasError)
                    {
                        return Result<AbstractUnique>.Fail();
                    }

                    return Result<AbstractUnique>.Success(eccResult.Ok);
                }
            default:
                {
                    return Result<AbstractUnique>.Fail();
                }
        }
    }

    /// <summary>
    ///     Decodes the TPM2B_PUBLIC_KEY_RSA from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPM2B_PUBLIC_KEY_RSA.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="RsaUnique" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<RsaUnique> DecodeRsaUnique(ref Span<byte> buffer)
    {
        // 11.2.4.6 TPM2B_PUBLIC_KEY_RSA
        // This Table 194 sized buffer holds the largest RSA public key supported by the TPM.
        // Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure
        // | Parameter                          | Type   | Description
        // | size                               | UINT16 | Size of the buffer. The value of zero is only valid for create.
        // | buffer[size] {: MAX_RSA_KEY_BYTES} | BYTE   | Value
        // The modulus length is checked against keyBits (and its most significant bit) in Decode() once both "parameters" and "unique" have been decoded.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L4149
        if (!TryConsume(ref buffer, 2, out var rawSize))
        {
            return Result<RsaUnique>.Fail();
        }

        var size = BinaryPrimitives.ReadUInt16BigEndian(rawSize);

        // "The value of zero is only valid for create."
        if (size == 0)
        {
            return Result<RsaUnique>.Fail();
        }

        if (!TryConsume(ref buffer, size, out var rawBuffer))
        {
            return Result<RsaUnique>.Fail();
        }

        var resultBuffer = new byte[size];
        if (!rawBuffer.TryCopyTo(resultBuffer.AsSpan()))
        {
            return Result<RsaUnique>.Fail();
        }

        var rsaUnique = new RsaUnique(resultBuffer);
        return Result<RsaUnique>.Success(rsaUnique);
    }

    /// <summary>
    ///     Decodes the TPMS_ECC_POINT from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPMS_ECC_POINT.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="EccUnique" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<EccUnique> DecodeEccUnique(ref Span<byte> buffer)
    {
        // 11.2.5.2 TPMS_ECC_POINT
        // This Table 198 structure holds two ECC coordinates that, together, make up an ECC point.
        // y is zero-length for the Edwards curves (Curve25519 and Curve448). See Part 1 for details on how ECC points are represented using this structure.
        // Definition of {ECC} TPMS_ECC_POINT Structure
        // | Parameter | Type                | Description
        // | x         | TPM2B_ECC_PARAMETER | X coordinate
        // | y         | TPM2B_ECC_PARAMETER | Y coordinate

        // 11.2.5.1 TPM2B_ECC_PARAMETER
        // This Table 197 sized buffer holds the largest ECC parameter (coordinate) supported by the TPM.
        // Definition of {ECC} TPM2B_ECC_PARAMETER Structure
        // | Parameter                         | Type   | Description
        // | size                              | UINT16 | Size of buffer
        // | buffer[size] {:MAX_ECC_KEY_BYTES} | BYTE   | The parameter data
        // The Edwards curves are not supported by this library, so an empty coordinate is rejected here;
        // the exact coordinate sizes are checked against the curve in Decode() once both "parameters" and "unique" have been decoded.
        // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L4256

        // x.size
        if (!TryConsume(ref buffer, 2, out var rawXSize))
        {
            return Result<EccUnique>.Fail();
        }

        var xSize = BinaryPrimitives.ReadUInt16BigEndian(rawXSize);
        if (xSize == 0)
        {
            return Result<EccUnique>.Fail();
        }

        // x.buffer
        if (!TryConsume(ref buffer, xSize, out var rawX))
        {
            return Result<EccUnique>.Fail();
        }

        var x = new byte[xSize];
        if (!rawX.TryCopyTo(x.AsSpan()))
        {
            return Result<EccUnique>.Fail();
        }

        // y.size
        if (!TryConsume(ref buffer, 2, out var rawYSize))
        {
            return Result<EccUnique>.Fail();
        }

        var ySize = BinaryPrimitives.ReadUInt16BigEndian(rawYSize);
        if (ySize == 0)
        {
            return Result<EccUnique>.Fail();
        }

        // y.buffer
        if (!TryConsume(ref buffer, ySize, out var rawY))
        {
            return Result<EccUnique>.Fail();
        }

        var y = new byte[ySize];
        if (!rawY.TryCopyTo(y.AsSpan()))
        {
            return Result<EccUnique>.Fail();
        }

        var eccUnique = new EccUnique(x, y);
        return Result<EccUnique>.Success(eccUnique);
    }

    /// <summary>
    ///     Returns the size in bytes of the digest produced by the specified hash algorithm.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm.</param>
    /// <param name="digestSize">Output parameter containing the digest size in bytes if the method returned <see langword="true" />; otherwise, 0.</param>
    /// <returns><see langword="true" /> if the digest size of <paramref name="hashAlg" /> is known; otherwise, <see langword="false" />.</returns>
    protected virtual bool TryGetDigestSize(TpmAlgIdHash hashAlg, out int digestSize)
    {
        // 10.2.1 TPMU_HA (Table 88) fixes the digest size per algorithm; the table is shared with the TPMS_ATTEST decoder, see TpmAlgIdHashExtensions.
        return hashAlg.TryGetDigestSize(out digestSize);
    }

    /// <summary>
    ///     Returns the size in bytes of one coordinate of a point on the specified elliptic curve.
    /// </summary>
    /// <param name="curve">The elliptic curve.</param>
    /// <param name="coordinateSize">Output parameter containing the coordinate size in bytes if the method returned <see langword="true" />; otherwise, 0.</param>
    /// <returns><see langword="true" /> if the coordinate size of <paramref name="curve" /> is known; otherwise, <see langword="false" />.</returns>
    protected virtual bool TryGetCoordinateSize(TpmiEccCurve curve, out int coordinateSize)
    {
        // CryptValidateKeys(): keySizeInBytes = BITS_TO_BYTES(CryptEccGetKeySizeForCurve(curveId));
        // CryptEccGetKeySizeForCurve() returns the keySizeBits of the curve from eccCurves[] (CryptEccData.c): 256 / 384 / 521 bits -> 32 / 48 / 66 bytes.
        switch (curve)
        {
            case TpmiEccCurve.TpmEccNistP256:
                {
                    coordinateSize = 32;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP384:
                {
                    coordinateSize = 48;
                    return true;
                }
            case TpmiEccCurve.TpmEccNistP521:
                {
                    // BITS_TO_BYTES(521) = 66
                    coordinateSize = 66;
                    return true;
                }
            default:
                {
                    coordinateSize = 0;
                    return false;
                }
        }
    }

    /// <summary>
    ///     Attempts to consume the specified number of bytes from the input Span and return them as a separate out parameter.
    /// </summary>
    /// <param name="input">Input Span from which it is necessary to consume the specified number of bytes.</param>
    /// <param name="bytesToConsume">The number of bytes that need to be consumed.</param>
    /// <param name="consumed">Output Span containing the consumed bytes if the operation was successful. </param>
    /// <returns>
    ///     If it returns <see langword="true" />, it means that the specified amount of bytes has been consumed from the input Span and the consumed bytes have been returned as a separate out parameter, simultaneously decreasing the input Span by the number of consumed bytes.
    ///     Otherwise, it returns <see langword="false" />, leaves the default value in the out parameter, and does not affect the input Span.
    /// </returns>
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
