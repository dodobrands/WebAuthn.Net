using System;
using System.Buffers.Binary;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

/// <summary>
///     Default implementation of <see cref="ITpmPubAreaDecoder" />.
/// </summary>
public class DefaultTpmPubAreaDecoder : ITpmPubAreaDecoder
{
    /// <inheritdoc />
    public virtual Result<PubArea> Decode(Span<byte> publicArea)
    {
        var buffer = publicArea;
        // "publicArea"
        // 12.2.4 TPMT_PUBLIC
        // Table defines the public area structure. The Name of the object is nameAlg concatenated with the digest of this structure using nameAlg.
        // Definition of TPMT_PUBLIC Structure
        // | Parameter        | Type              | Description
        // | type             | TPMI_ALG_PUBLIC   | "Algorithm" associated with this object
        // | nameAlg          | +TPMI_ALG_HASH    | Algorithm used for computing the Name of the object. Note: The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to indicate that the nameAlg may be TPM_ALG_NULL.
        // | objectAttributes | TPMA_OBJECT       | Attributes that, along with "type", determine the manipulations of this object
        // | authPolicy       | TPM2B_DIGEST      | Optional policy for using this key. The policy is computed using the "nameAlg" of the object. Note: This is the Empty Policy if no authorization policy is present.
        // | [type]parameters | TPMU_PUBLIC_PARMS | The algorithm or structure details.
        // | [type]unique     | TPMU_PUBLIC_ID    | The unique identifier of the structure. For an asymmetric key, this would be the public key.

        // ---------------------------------------
        // "publicArea"."type"
        // 12.2.2 TPMI_ALG_PUBLIC
        // defines the TPMI_ALG_PUBLIC type.
        // Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type
        // | Values         | Comments
        // | TPM_ALG_!ALG.o |
        // We do not support any algorithms other than RSA and ECC.
        // 6.3 TPM_ALG_ID
        // Definition of (UINT16) TPM_ALG_ID Constants
        // | Algorithm Name | TCG_ALG Value | Reference       | Comments
        // | TPM_ALG_RSA    | 0x0001        | IETF RFC 8017   | the RSA algorithm
        // | TPM_ALG_ECC    | 0x0023        | ISO/IEC 15946-1 | prime field ECC
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
        // Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type
        // | Values         | Comments
        // | TPM_ALG_!ALG.H | all hash algorithms defined by the TCG
        // | +TPM_ALG_NULL  |
        // "nameAlg" is not needed for the rest of WebAuthn processing, so we just consume and skip it
        if (!TryConsume(ref buffer, 2, out _))
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
        // |    16 | restricted           | SET (1): Key usage is restricted to manipulate structures of known format; the parent of this key shall have restricted SET.
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

        var objectAttributes = (ObjectAttributes) BinaryPrimitives.ReadUInt32BigEndian(rawObjectAttributes);

        // ---------------------------------------
        // "publicArea"."authPolicy"
        // 10.4.2 TPM2B_DIGEST
        // The Table structure is used for a sized buffer that cannot be larger than the largest digest produced by any hash algorithm implemented on the TPM.
        // As with all sized buffers, the size is checked to see if it is within the prescribed range. If not, the response code is TPM_RC_SIZE.
        // NOTE:
        // For any structure, like the one below, that contains an implied size check, it is implied that TPM_RC_SIZE is a possible response code and the response code will not be listed in the table.
        // Definition of TPM2B_DIGEST Structure
        // | Parameter                      | Type   | Description
        // | size                           | UINT16 | size in octets of the buffer field; may be 0
        // | buffer[size]{:sizeof(TPMU_HA)} | BYTE   | the buffer area that can be no larger than a digest
        // "authPolicy" is not needed for the rest of WebAuthn processing, so we just consume and skip it
        if (!TryConsume(ref buffer, 2, out var rawAuthPolicySize))
        {
            return Result<PubArea>.Fail();
        }

        var authPolicySize = BinaryPrimitives.ReadUInt16BigEndian(rawAuthPolicySize);
        if (authPolicySize > 0)
        {
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

        if (buffer.Length > 0)
        {
            return Result<PubArea>.Fail();
        }

        var pubArea = new PubArea(
            type,
            publicParmsResult.Ok,
            uniqueResult.Ok);
        return Result<PubArea>.Success(pubArea);
    }

    /// <summary>
    ///     Decodes the TPMS_ASYM_PARMS from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPMS_ASYM_PARMS.</param>
    /// <param name="type">Type of asymmetric algorithm with a public and private key, used by the TPM module for generating digital signatures in the process of WebAuthn ceremonies.</param>
    /// <param name="objectAttributes">Flags that indicate an object's use, its authorization types, and its relationship to other objects. The state of the attributes is determined when the object is created and they are never changed by the TPM.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AbstractPublicParms" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<AbstractPublicParms> DecodePublicParms(
        ref Span<byte> buffer,
        TpmAlgPublic type,
        ObjectAttributes objectAttributes)
    {
        // "publicArea"."[type]parameters"
        // 12.2.3.7 TPMU_PUBLIC_PARMS
        // Table defines the possible parameter definition structures that may be contained in the public portion of a key.
        // Definition of TPMU_PUBLIC_PARMS Union <IN/OUT>
        // | Parameter         | Type                  | Selector           | Description (1)
        // | keyedHashDetail   | TPMS_KEYEDHASH_PARMS  | TPM_ALG_KEYEDHASH  | "sign | decrypt | neither (2)"
        // | symDetail         | TPMS_SYMCIPHER_PARMS  | TPM_ALG_SYMCIPHER  | "sign | decrypt | neither (2)"
        // | rsaDetail         | TPMS_RSA_PARMS        | TPM_ALG_RSA        | "decrypt + sign (2)"
        // | eccDetail         | TPMS_ECC_PARMS        | TPM_ALG_ECC        | "decrypt + sign (2)"
        // | asymDetail        | TPMS_ASYM_PARMS       |                    | common scheme structure for RSA and ECC keys
        //  NOTE:
        //   [1] The Description column indicates which of TPMA_OBJECT.decrypt or TPMA_OBJECT.sign may be set.
        //   [2] "+" indicates that both may be set but one shall be set. "|" indicates the optional settings.

        var canDecrypt = (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        var canSign = (objectAttributes & ObjectAttributes.SignEncrypt) == ObjectAttributes.SignEncrypt;

        // "decrypt + sign (2)" for `rsaDetail` and `eccDetail`
        if (!canDecrypt && !canSign)
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
        // 12.2.3.5 TPMS_RSA_PARMS
        // Table defines the TPMS_RSA_PARMS structure.
        // A TPM compatible with this specification and supporting RSA shall support two primes and an exponent of zero.
        // An exponent of zero indicates that the exponent is the default of 216 + 1.
        // Support for other values is optional.
        // Use of other exponents in duplicated keys is not recommended because the resulting keys would not be interoperable with other TPMs.
        // Support for other values is optional.
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
        // | keyBits   | TPMI_RSA_KEY_BITS    | number of bits in the public modulus
        // | exponent  | UINT32               | exponent an odd number greater than 2

        // We do not expect to receive a restricted decryption key at this point.
        var isRestrictedDecryptionKey =
            (objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted
            && (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        if (isRestrictedDecryptionKey)
        {
            return Result<RsaParms>.Fail();
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."symmetric"
        // 11.1.7 TPMT_SYM_DEF_OBJECT
        // This Table structure is used when different symmetric block cipher (not XOR) algorithms may be selected.
        // If the Object can be an ordinary parent (not a derivation parent), this must be the first field in the Object's parameter (see clause 12.2.3.7) field.
        // Definition of TPMT_SYM_DEF_OBJECT Structure
        // | Parameter          | Type                 | Description
        // | algorithm          | +TPMI_ALG_SYM_OBJECT | Selects a symmetric block cipher
        // |                    |                      | When used in the parameter area of a parent object, this shall be a supported block cipher and not TPM_ALG_NULL
        // | [algorithm]keyBits | TPMU_SYM_KEY_BITS    | The key size
        // | [algorithm]mode    | TPMU_SYM_MODE        | Default mode. When used in the parameter area of a parent object, this shall be TPM_ALG_CFB.
        // | [algorithm]details | TPMU_SYM_DETAILS     | Contains the additional algorithm details, if any

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
        // 11.2.4.2 TPMT_RSA_SCHEME
        // Definition of {RSA} TPMT_RSA_SCHEME Structure
        // | Parameter       | Type                 | Description
        // | scheme          | +TPMI_ALG_RSA_SCHEME | scheme selector
        // | [scheme]details | TPMU_ASYM_SCHEME     | scheme parameters

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."scheme"."scheme"
        // 11.2.4.1 TPMI_ALG_RSA_SCHEME
        // Definition of (TPM_ALG_ID) {RSA} TPMI_ALG_RSA_SCHEME Type
        // | Values             | Comments
        // | TPM_ALG_!ALG.ae.ax | Encrypting and signing algorithms
        // | +TPM_ALG_NULL      |

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

        // signing key
        if ((objectAttributes & ObjectAttributes.SignEncrypt) == ObjectAttributes.SignEncrypt)
        {
            // restricted signing key
            if ((objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted)
            {
                // for a restricted signing key, either TPM_ALG_RSAPSS or TPM_ALG_RSASSA
                if (scheme != TpmiAlgRsaScheme.TpmAlgRsapss && scheme != TpmiAlgRsaScheme.TpmAlgRsassa)
                {
                    return Result<RsaParms>.Fail();
                }
            }
            else // unrestricted signing key
            {
                // for an unrestricted signing key, either TPM_ALG_RSAPSS TPM_ALG_RSASSA or TPM_ALG_NULL
                if (scheme != TpmiAlgRsaScheme.TpmAlgRsapss && scheme != TpmiAlgRsaScheme.TpmAlgRsassa && scheme != TpmiAlgRsaScheme.TpmAlgNull)
                {
                    return Result<RsaParms>.Fail();
                }
            }
        }

        // decryption key
        if ((objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt)
        {
            // restricted decryption key
            if ((objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted)
            {
                // for a restricted decryption key, TPM_ALG_NULL
                if (scheme != TpmiAlgRsaScheme.TpmAlgNull)
                {
                    return Result<RsaParms>.Fail();
                }
            }
            else // unrestricted decryption key
            {
                // for an unrestricted decryption key, TPM_ALG_RSAES, TPM_ALG_OAEP, or TPM_ALG_NULL unless the object also has the "sign" attribute

                // does not have the "sign" attribute
                if ((objectAttributes & ObjectAttributes.SignEncrypt) != ObjectAttributes.SignEncrypt)
                {
                    if (scheme != TpmiAlgRsaScheme.TpmAlgRsaes && scheme != TpmiAlgRsaScheme.TpmAlgOaep && scheme != TpmiAlgRsaScheme.TpmAlgNull)
                    {
                        return Result<RsaParms>.Fail();
                    }
                }
                else // has the "sign" attribute
                {
                    if (scheme is TpmiAlgRsaScheme.TpmAlgRsaes or TpmiAlgRsaScheme.TpmAlgOaep)
                    {
                        return Result<RsaParms>.Fail();
                    }
                }
            }
        }

        // when both "sign" and "decrypt" are SET, restricted shall be CLEAR and "scheme" shall be TPM_ALG_NULL
        if (((objectAttributes & ObjectAttributes.SignEncrypt) == ObjectAttributes.SignEncrypt)
            && ((objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt))
        {
            var restrictedClear = ((objectAttributes & ObjectAttributes.Restricted) != ObjectAttributes.Restricted);
            var schemeNull = (scheme == TpmiAlgRsaScheme.TpmAlgNull);
            var bothConditionsAreTrue = restrictedClear && schemeNull;
            if (!bothConditionsAreTrue)
            {
                return Result<RsaParms>.Fail();
            }
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."scheme"."[scheme]details"
        // 11.2.3.5 TPMU_ASYM_SCHEME
        // This Table union of all asymmetric schemes is used in each of the asymmetric scheme structures.
        // The actual scheme structure is defined by the interface type used for the selector (TPMI_ALG_ASYM_SCHEME).
        // EXAMPLE:
        //  The TPMT_RSA_SCHEME structure uses the TPMU_ASYM_SCHEME union but the selector type is TPMI_ALG_RSA_SCHEME.
        //  This means that the only elements of the union that can be selected for the TPMT_RSA_SCHEME are those that are in TPMI_RSA_SCHEME.
        // Definition of TPMU_ASYM_SCHEME Union
        // | Parameter | Type                 | Selector     | Description
        // | !ALG.am   | TPMS_KEY_SCHEME_!ALG | TPM_ALG_!ALG |
        // | !ALG.ax   | TPMS_SIG_SCHEME_!ALG | TPM_ALG_!ALG | Signing and anonymous signing
        // | !ALG.ae   | TPMS_ENC_SCHEME_!ALG | TPM_ALG_!ALG | Schemes with no hash
        // | anySig    | TPMS_SCHEME_HASH     | TPM_ALG_OAEP |
        // | null      |                      | TPM_ALG_NULL | no scheme or default

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
        if (scheme == TpmiAlgRsaScheme.TpmAlgRsassa
            || scheme == TpmiAlgRsaScheme.TpmAlgRsapss
            || scheme == TpmiAlgRsaScheme.TpmAlgOaep)
        {
            // consume hashAlg
            if (!TryConsume(ref buffer, 2, out _))
            {
                return Result<RsaParms>.Fail();
            }
        }

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."keyBits"
        // 11.2.4.6 TPMI_RSA_KEY_BITS
        // This Table holds the value that is the maximum size allowed for an RSA key.
        // NOTE 1:
        //  An implementation is allowed to provide limited support for smaller RSA key sizes.
        //  That is, a TPM may be able to accept a smaller RSA key size in TPM2_LoadExternal()
        //  when only the public area is loaded but not accept that smaller key size in any command
        //  that loads both the public and private portions of an RSA key.
        //  This would allow the TPM to validate signatures using the smaller key but would prevent
        //  the TPM from using the smaller key size for any other purpose.
        // NOTE 2:
        //  The definition for RSA_KEY_SIZES_BITS used in the reference implementation is found in TPM 2.0 Part 4, Implementation.h
        // Definition of {RSA} (TPM_KEY_BITS) TPMI_RSA_KEY_BITS Type
        // | Parameter           | Description
        // | $RSA_KEY_SIZES_BITS | The number of bits in the supported key
        // 5.3 Miscellaneous Types
        // Table defines types either for compatibility with previous versions of this specification or for clarity of this specification.
        // Definition of Types for Documentation Clarity
        // | Type   | Name         | Description
        // | UINT16 | TPM_KEY_BITS | A key size in bits

        // "keyBits" is not needed for the rest of WebAuthn processing, so we just consume and skip it.
        if (!TryConsume(ref buffer, 2, out _))
        {
            return Result<RsaParms>.Fail();
        }

        // "publicArea"."[TPM_ALG_RSA]parameters"."rsaDetail"."exponent"
        if (!TryConsume(ref buffer, 4, out var rawExponent))
        {
            return Result<RsaParms>.Fail();
        }

        var exponent = BinaryPrimitives.ReadUInt32BigEndian(rawExponent);
        // An exponent of zero indicates that the exponent is the default of 2^16 + 1.
        if (exponent is 0)
        {
            exponent = 65537U;
        }

        var rsaDetail = new RsaParms(exponent);
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
        // 12.2.3.6 TPMS_ECC_PARMS
        // This Table structure contains the parameters for prime modulus ECC.
        // Definition of {ECC} TPMS_ECC_PARMS Structure
        // | Parameter | Type                 | Description
        // | symmetric | TPMT_SYM_DEF_OBJECT+ | For a restricted decryption key, shall be set to a supported symmetric algorithm, key size. and mode.
        // |           |                      | If the key is not a restricted decryption key, this field shall be set to TPM_ALG_NULL.
        // | scheme    | TPMT_ECC_SCHEME+     | If the sign attribute of the key is SET, then this shall be a valid signing scheme.
        // |           |                      | If the sign parameter in curveID indicates a mandatory scheme, then this field shall have the same value.
        // |           |                      | If the decrypt attribute of the key is SET, then this shall be a valid key exchange scheme or TPM_ALG_NULL.
        // |           |                      | If the key is a Storage Key, then this field shall be TPM_ALG_NULL.
        // | curveID   | TPMI_ECC_CURVE       | ECC curve ID
        // | kdf       | TPMT_KDF_SCHEME+     | An optional key derivation scheme for generating a symmetric key from a Z value
        // |           |                      | If the kdf parameter associated with curveID is not TPM_ALG_NULL then this is required to be NULL.
        // |           |                      |  NOTE: There are currently no commands where this parameter has effect and, in the reference code, this field needs to be set to TPM_ALG_NULL.

        // We do not expect to receive a restricted decryption key at this point.
        var isRestrictedDecryptionKey =
            (objectAttributes & ObjectAttributes.Restricted) == ObjectAttributes.Restricted
            && (objectAttributes & ObjectAttributes.Decrypt) == ObjectAttributes.Decrypt;
        if (isRestrictedDecryptionKey)
        {
            return Result<EccParms>.Fail();
        }

        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf
        // A restricted decryption key is often referred to in this specification as a Storage Key.

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."symmetric"
        // 11.1.7 TPMT_SYM_DEF_OBJECT
        // This Table structure is used when different symmetric block cipher (not XOR) algorithms may be selected.
        // If the Object can be an ordinary parent (not a derivation parent), this must be the first field in the Object's parameter (see clause 12.2.3.7) field.
        // Definition of TPMT_SYM_DEF_OBJECT Structure
        // | Parameter          | Type                 | Description
        // | algorithm          | +TPMI_ALG_SYM_OBJECT | Selects a symmetric block cipher
        // |                    |                      | When used in the parameter area of a parent object, this shall be a supported block cipher and not TPM_ALG_NULL
        // | [algorithm]keyBits | TPMU_SYM_KEY_BITS    | The key size
        // | [algorithm]mode    | TPMU_SYM_MODE        | Default mode. When used in the parameter area of a parent object, this shall be TPM_ALG_CFB.
        // | [algorithm]details | TPMU_SYM_DETAILS     | Contains the additional algorithm details, if any

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
        // 11.2.5.6 TPMT_ECC_SCHEME
        // Definition of (TPMT_SIG_SCHEME) {ECC} TPMT_ECC_SCHEME Structure
        // | Parameter       | Type                 | Description
        // | scheme          | +TPMI_ALG_ECC_SCHEME | scheme selector
        // | [scheme]details | TPMU_ASYM_SCHEME     | scheme parameters

        // ------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."scheme"."scheme"
        // 11.2.5.4 TPMI_ALG_ECC_SCHEME
        // Definition of (TPM_ALG_ID) {ECC} TPMI_ALG_ECC_SCHEME Type
        // | Values          | Comments
        // | TPM_ALG_!ALG.ax | the ecc signing schemes
        // | TPM_ALG_!ALG.am | key exchange methods
        // | +TPM_ALG_NULL   |

        // TPM_ALG_NULL = 0x0010
        // TPM_ALG_ECDSA 0x0018 (A X) - asymmetric algorithm with a public and private key + signing algorithm
        // TPM_ALG_ECDH 0x0019 (A M) - asymmetric algorithm with a public and private key + a method such as a mask generation function
        // TPM_ALG_ECDAA 0x001A (A X N) - asymmetric algorithm with a public and private key + signing algorithm + an anonymous signing algorithm
        // TPM_ALG_SM2 0x001B (A X E M) - asymmetric algorithm with a public and private key + signing algorithm +  an encryption algorithm + a method such as a mask generation function
        // TPM_ALG_ECSCHNORR 0x001C (A X) - asymmetric algorithm with a public and private key + signing algorithm
        // TPM_ALG_ECMQV 0x001D (A M) - asymmetric algorithm with a public and private key + a method such as a mask generation function
        // TPM_ALG_EDDSA 0x0060 (A X) - asymmetric algorithm with a public and private key + signing algorithm
        // TPM_ALG_EDDSA_PH 0x0061 (A X) - asymmetric algorithm with a public and private key + signing algorithm

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

        // ---------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."scheme"."[scheme]details"
        // 11.2.3.5 TPMU_ASYM_SCHEME
        // This Table union of all asymmetric schemes is used in each of the asymmetric scheme structures.
        // The actual scheme structure is defined by the interface type used for the selector (TPMI_ALG_ASYM_SCHEME).
        // EXAMPLE:
        //  The TPMT_RSA_SCHEME structure uses the TPMU_ASYM_SCHEME union but the selector type is TPMI_ALG_RSA_SCHEME.
        //  This means that the only elements of the union that can be selected for the TPMT_RSA_SCHEME are those that are in TPMI_RSA_SCHEME.
        // Definition of TPMU_ASYM_SCHEME Union
        // | Parameter | Type                 | Selector     | Description
        // | !ALG.am   | TPMS_KEY_SCHEME_!ALG | TPM_ALG_!ALG |
        // | !ALG.ax   | TPMS_SIG_SCHEME_!ALG | TPM_ALG_!ALG | Signing and anonymous signing
        // | !ALG.ae   | TPMS_ENC_SCHEME_!ALG | TPM_ALG_!ALG | Schemes with no hash
        // | anySig    | TPMS_SCHEME_HASH     | TPM_ALG_OAEP |
        // | null      |                      | TPM_ALG_NULL | no scheme or default

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

        if (scheme is TpmiAlgEccScheme.TpmAlgEcdsa
            or TpmiAlgEccScheme.TpmAlgEcdaa
            or TpmiAlgEccScheme.TpmAlgSm2
            or TpmiAlgEccScheme.TpmAlgEcschnorr
            or TpmiAlgEccScheme.TpmAlgEddsa
            or TpmiAlgEccScheme.TpmAlgEddsaPh
            or TpmiAlgEccScheme.TpmAlgEcdh
            or TpmiAlgEccScheme.TpmAlgEcmqv)
        {
            // consume hashAlg
            if (!TryConsume(ref buffer, 2, out _))
            {
                return Result<EccParms>.Fail();
            }
        }

        if (scheme is TpmiAlgEccScheme.TpmAlgEcdaa)
        {
            // consume count
            if (!TryConsume(ref buffer, 2, out _))
            {
                return Result<EccParms>.Fail();
            }
        }
        // ------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."curveID"
        // 11.2.5.5 TPMI_ECC_CURVE
        // Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type
        // | Parameter     | Description
        // | $ECC_CURVES   | the list of implemented curves
        // | +TPM_ECC_NONE | scheme parameters

        // 6.4 TPM_ECC_CURVE
        // The TCG maintains a registry of all curves that have an assigned curve identifier.
        // That registry is the definitive list of curves that may be supported by a TPM.
        // Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT>
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

        if (!TryConsume(ref buffer, 2, out var rawCurveId))
        {
            return Result<EccParms>.Fail();
        }

        var curveId = (TpmiEccCurve) BinaryPrimitives.ReadUInt16BigEndian(rawCurveId);

        // We currently support only:
        // TPM_ECC_NIST_P256
        // TPM_ECC_NIST_P384
        // TPM_ECC_NIST_P521
        if (!Enum.IsDefined(curveId))
        {
            return Result<EccParms>.Fail();
        }
        // ------------------------------------
        // "publicArea"."[TPM_ALG_ECC]parameters"."eccDetail"."kdf"
        // 11.2.3.3 TPMT_KDF_SCHEME
        // Definition of TPMT_KDF_SCHEME Structure
        // | Parameter       | Type            | Description
        // | scheme          | +TPMI_ALG_KDF   | scheme selector
        // | [scheme]details | TPMU_KDF_SCHEME | scheme parameters

        if (!TryConsume(ref buffer, 2, out var rawKdfScheme))
        {
            return Result<EccParms>.Fail();
        }

        var kdfScheme = (TpmiAlgKdf) BinaryPrimitives.ReadUInt16BigEndian(rawKdfScheme);
        if (kdfScheme != TpmiAlgKdf.TpmAlgNull)
        {
            // TPM_ALG_MGF1 => TPMS_KDF_SCHEME_MGF1_Marshal => TPMS_SCHEME_HASH_Marshal
            // TPM_ALG_KDF1_SP800_56A => TPMS_KDF_SCHEME_KDF1_SP800_56A_Marshal => TPMS_SCHEME_HASH_Marshal
            // TPM_ALG_KDF2 => TPMS_KDF_SCHEME_KDF2_Marshal => TPMS_SCHEME_HASH_Marshal
            // TPM_ALG_KDF1_SP800_108 => TPMS_KDF_SCHEME_KDF1_SP800_108_Marshal => TPMS_SCHEME_HASH_Marshal
            // https://github.com/TrustedComputingGroup/TPM/blob/3b1f0e623f244abe2015df9e3ba86de5c9118524/TPMCmd/tpm/src/support/Marshal.c#L3361
            // TPMS_SCHEME_HASH_Marshal => TPMI_ALG_HASH_Marshal
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

            // consume hashAlg
            if (!TryConsume(ref buffer, 2, out var rawKdfSchemeHashAlg))
            {
                return Result<EccParms>.Fail();
            }

            // var kdfSchemeHashAlg = BinaryPrimitives.ReadUInt16BigEndian(rawKdfSchemeHashAlg);
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
        // This Table is the union of all values allowed in in the unique field of a TPMT_PUBLIC.
        // NOTE:
        //  The derive member cannot be unmarshaled in a TPMU_PUBLIC_ID.
        //  It is placed in this structure so that the maximum size of a TPM2B_TEMPLATE will be computed correctly.
        // Definition of TPMU_PUBLIC_ID Union <IN/OUT>
        // | Parameter | Type                 | Selector          | Description
        // | keyedHash | TPM2B_DIGEST         | TPM_ALG_KEYEDHASH |
        // | sym       | TPM2B_DIGEST         | TPM_ALG_SYMCIPHER |
        // | rsa       | TPM2B_PUBLIC_KEY_RSA | TPM_ALG_RSA       |
        // | ecc       | TPMS_ECC_POINT       | TPM_ALG_ECC       |
        // | derive    | TPMS_DERIVE          |                   | only allowed for TPM2_CreateLoaded when parentHandle is a Derivation Parent.
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
        // 11.2.4.5 TPM2B_PUBLIC_KEY_RSA
        // This sized buffer holds the largest RSA public key supported by the TPM
        // Note:
        //  The reference implementation only supports key sizes of 1,024 and 2,048 bits.
        // Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure
        // | Parameter                          | Type   | Description
        // | size                               | UINT16 | Size of the buffer. The value of zero is only valid for create.
        // | buffer[size] {: MAX_RSA_KEY_BYTES} | BYTE   | Value
        if (!TryConsume(ref buffer, 2, out var rawSize))
        {
            return Result<RsaUnique>.Fail();
        }

        var size = BinaryPrimitives.ReadUInt16BigEndian(rawSize);

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
        // This Table structure holds two ECC coordinates that, together, make up an ECC point
        // Definition of {ECC} TPMS_ECC_POINT Structure
        // | Parameter | Type                | Description
        // | x         | TPM2B_ECC_PARAMETER | X coordinate
        // | y         | TPM2B_ECC_PARAMETER | Y coordinate

        // 11.2.5.1 TPM2B_ECC_PARAMETER
        // This Table sized buffer holds the largest ECC parameter (coordinate) supported by the TPM.
        // Definition of {ECC} TPM2B_ECC_PARAMETER Structure
        // | Parameter                         | Type   | Description
        // | size                              | UINT16 | Size of buffer
        // | buffer[size] {:MAX_ECC_KEY_BYTES} | BYTE   | The parameter data

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
