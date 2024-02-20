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
    public virtual Result<PubArea> Decode(Span<byte> bytes)
    {
        var buffer = bytes;
        // 12.2.4 TPMT_PUBLIC
        // Table 200 defines the public area structure. The Name of the object is nameAlg concatenated with the digest of this structure using nameAlg.
        // Table 200 — Definition of TPMT_PUBLIC Structure
        // | Parameter        | Type              | Description
        // | type             | TPMI_ALG_PUBLIC   | "Algorithm" associated with this object.
        // | nameAlg          | +TPMI_ALG_HASH    | Algorithm used for computing the Name of the object. Note: The "+" indicates that the instance of a TPMT_PUBLIC may have a "+" to indicate that the nameAlg may be TPM_ALG_NULL.
        // | objectAttributes | TPMA_OBJECT       | Attributes that, along with type, determine the manipulations of this object.
        // | authPolicy       | TPM2B_DIGEST      | Optional policy for using this key. The policy is computed using the nameAlg of the object. Note: Shall be the Empty Policy if no authorization policy is present.
        // | [type]parameters | TPMU_PUBLIC_PARMS | The algorithm or structure details.
        // | [type]unique     | TPMU_PUBLIC_ID    | The unique identifier of the structure. For an asymmetric key, this would be the public key.

        // type
        if (!TryConsume(ref buffer, 2, out var rawType))
        {
            return Result<PubArea>.Fail();
        }

        var type = (TpmAlgPublic) BinaryPrimitives.ReadUInt16BigEndian(rawType);
        if (!Enum.IsDefined(type))
        {
            return Result<PubArea>.Fail();
        }

        // nameAlg
        if (!TryConsume(ref buffer, 2, out var rawNameAlg))
        {
            return Result<PubArea>.Fail();
        }

        var nameAlg = (TpmAlgIdHash) BinaryPrimitives.ReadUInt16BigEndian(rawNameAlg);
        if (!Enum.IsDefined(nameAlg))
        {
            return Result<PubArea>.Fail();
        }

        // objectAttributes
        if (!TryConsume(ref buffer, 4, out var rawObjectAttributes))
        {
            return Result<PubArea>.Fail();
        }

        var objectAttributes = (ObjectAttributes) BinaryPrimitives.ReadUInt32BigEndian(rawObjectAttributes);

        // authPolicy
        // 10.4.2 TPM2B_DIGEST
        // This structure is used for a sized buffer that cannot be larger than the largest digest produced by any hash algorithm implemented on the TPM.
        // Table 80 — Definition of TPM2B_DIGEST Structure
        // | Parameter                      | Type           | Description
        // | size                           | UINT16         | size in octets of the buffer field; may be 0
        // | buffer[size]{:sizeof(TPMU_HA)} | +TPMI_ALG_HASH | the buffer area that can be no larger than a digest
        // ------
        // skip authPolicy
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

        // [type]parameters
        var publicParmsResult = DecodePublicParms(ref buffer, type, objectAttributes);
        if (publicParmsResult.HasError)
        {
            return Result<PubArea>.Fail();
        }

        //[type]unique
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
            nameAlg,
            objectAttributes,
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
        // 12.2.3.4 TPMS_ASYM_PARMS
        // This structure contains the common public area parameters for an asymmetric key.
        // The first two parameters of the parameter definition structures of an asymmetric key shall have the same two first components.
        // Table 195 — Definition of TPMS_ASYM_PARMS Structure <>
        // | Parameter | Type                 | Description
        // | symmetric | TPMT_SYM_DEF_OBJECT+ | The companion symmetric algorithm for a restricted decryption key and shall be set to a supported symmetric algorithm. This field is optional for keys that are not decryption keys and shall be set to TPM_ALG_NULL if not used.
        // | scheme    | TPMT_ASYM_SCHEME+    | For a key with the sign attribute SET, a valid signing scheme for the key type
        // |           |                      | For a key with the decrypt attribute SET, a valid key exchange protocol.
        // |           |                      | For a key with sign and decrypt attributes, shall be TPM_ALG_NULL.
        // The symmetric and scheme properties vary for RSA and ECC
        switch (type)
        {
            case TpmAlgPublic.Rsa:
                {
                    var rsaResult = DecodeRsaParms(ref buffer, objectAttributes);
                    if (rsaResult.HasError)
                    {
                        return Result<AbstractPublicParms>.Fail();
                    }

                    return Result<AbstractPublicParms>.Success(rsaResult.Ok);
                }
            case TpmAlgPublic.Ecc:
                {
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
            return Result<RsaParms>.Fail();
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
            return Result<RsaParms>.Fail();
        }

        var symmetricAlgorithm = (TpmiAlgSymObject) BinaryPrimitives.ReadUInt16BigEndian(rawSymmetricAlgorithm);
        if (symmetricAlgorithm != TpmiAlgSymObject.TpmAlgNull)
        {
            return Result<RsaParms>.Fail();
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
            return Result<RsaParms>.Fail();
        }

        if (!TryConsume(ref buffer, 2, out var rawScheme))
        {
            return Result<RsaParms>.Fail();
        }

        var scheme = (TpmiAlgRsaScheme) BinaryPrimitives.ReadUInt16BigEndian(rawScheme);
        if (scheme != TpmiAlgRsaScheme.TpmAlgNull)
        {
            return Result<RsaParms>.Fail();
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
            return Result<RsaParms>.Fail();
        }

        var keyBits = BinaryPrimitives.ReadUInt16BigEndian(rawKeyBits);

        // exponent
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
            return Result<EccParms>.Fail();
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
            return Result<EccParms>.Fail();
        }

        var symmetricAlgorithm = (TpmiAlgSymObject) BinaryPrimitives.ReadUInt16BigEndian(rawSymmetricAlgorithm);
        if (symmetricAlgorithm != TpmiAlgSymObject.TpmAlgNull)
        {
            return Result<EccParms>.Fail();
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
            return Result<EccParms>.Fail();
        }

        var scheme = (TpmiAlgEccScheme) BinaryPrimitives.ReadUInt16BigEndian(rawScheme);
        if (scheme != TpmiAlgEccScheme.TpmAlgNull)
        {
            return Result<EccParms>.Fail();
        }
        //[scheme]details is ignored if the scheme is TPM_ALG_NULL

        // curveID
        // 11.2.5.5 TPMI_ECC_CURVE
        // Table 181 — Definition of {ECC} (TPM_ECC_CURVE) TPMI_ECC_CURVE Type
        // | Parameter   | Description
        // | $ECC_CURVES | The list of implemented curves
        if (!TryConsume(ref buffer, 2, out var rawCurveId))
        {
            return Result<EccParms>.Fail();
        }

        var curveId = (TpmiEccCurve) BinaryPrimitives.ReadUInt16BigEndian(rawCurveId);
        if (!Enum.IsDefined(curveId))
        {
            return Result<EccParms>.Fail();
        }

        // kdf
        // 11.2.3.3 TPMT_KDF_SCHEME
        // Table 166 — Definition of TPMT_KDF_SCHEME Structure
        // | Parameter       | Type            | Description
        // | scheme          | +TPMI_ALG_KDF   | Scheme selector
        // | [scheme]details | TPMU_KDF_SCHEME | Scheme parameters
        if (!TryConsume(ref buffer, 2, out var rawKdfScheme))
        {
            return Result<EccParms>.Fail();
        }

        var kdfScheme = (TpmiAlgKdf) BinaryPrimitives.ReadUInt16BigEndian(rawKdfScheme);
        // We do not expect any other kdf.scheme than TPM_ALG_NULL.
        if (kdfScheme != TpmiAlgKdf.TpmAlgNull)
        {
            return Result<EccParms>.Fail();
        }

        //[scheme]details is ignored if the scheme is TPM_ALG_NULL
        var eccDetail = new EccParms(curveId);
        return Result<EccParms>.Success(eccDetail);
    }

    /// <summary>
    ///     Decodes the TPMU_PUBLIC_ID from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="buffer">Buffer containing the binary representation of TPMU_PUBLIC_ID.</param>
    /// <param name="type">Type of asymmetric algorithm with a public and private key, used by the TPM module for generating digital signatures in the process of WebAuthn ceremonies.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AbstractUnique" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    protected virtual Result<AbstractUnique> DecodeUnique(
        ref Span<byte> buffer,
        TpmAlgPublic type)
    {
        // 12.2.3.2 TPMU_PUBLIC_ID
        // This is the union of all values allowed in in the unique field of a TPMT_PUBLIC
        // Table 193 — Definition of TPMU_PUBLIC_ID Union <IN/OUT>
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
        // Table 174 — Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure
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
