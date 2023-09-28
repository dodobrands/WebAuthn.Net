using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.RegistrationCeremony.Verification;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification;

public class DefaultTpmAttestationStatementVerifier : ITpmAttestationStatementVerifier
{
    public Result<AttestationStatementVerificationResult> Verify(
        TpmAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1 - Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2 - Verify that the public key specified by the parameters and unique fields of pubArea
        // is identical to the credentialPublicKey in the attestedCredentialData in authenticatorData.
        if (!PubArea.TryParse(attStmt.PubArea, out var pubArea))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!PubAreaKeySameAsAttestedCredentialData(pubArea, authData.AttestedCredentialData.CredentialPublicKey))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3 - Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        var attToBeSigned = Concat(authData.RawAuthData, clientDataHash);

        // 4 - Validate that certInfo is valid
        if (!IsCertInfoValid(attStmt.CertInfo))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        throw new NotImplementedException();
    }

    private static bool PubAreaKeySameAsAttestedCredentialData(PubArea pubArea, AbstractCoseKey authDataKey)
    {
        switch (pubArea.Type)
        {
            case TpmAlgPublic.Rsa:
                {
                    if (pubArea.Unique is not RsaUnique pubAreaRsaUnique)
                    {
                        return false;
                    }

                    if (pubArea.Parameters is not RsaParms pubAreaRsaParms)
                    {
                        return false;
                    }

                    if (authDataKey is not CoseRsaKey authDataRsa)
                    {
                        return false;
                    }

                    if (!pubAreaRsaUnique.Buffer.AsSpan().SequenceEqual(authDataRsa.ModulusN.AsSpan()))
                    {
                        return false;
                    }

                    if (!TryGetExponent(authDataRsa.PublicExponentE, out var authDataExponent))
                    {
                        return false;
                    }

                    if (pubAreaRsaParms.Exponent != authDataExponent.Value)
                    {
                        return false;
                    }

                    return true;
                }
            case TpmAlgPublic.Ecc:
                {
                    if (pubArea.Unique is not EccUnique pubAreaEccUnique)
                    {
                        return false;
                    }

                    if (pubArea.Parameters is not EccParms pubAreaEccParms)
                    {
                        return false;
                    }

                    if (authDataKey is not CoseEc2Key authDataEc2)
                    {
                        return false;
                    }

                    if (!TryCoseEllipticCurveToTpm(authDataEc2.Crv, out var authDataTpmCrv))
                    {
                        return false;
                    }

                    if (pubAreaEccParms.CurveId != authDataTpmCrv.Value)
                    {
                        return false;
                    }

                    if (!pubAreaEccUnique.X.AsSpan().SequenceEqual(authDataEc2.X.AsSpan()))
                    {
                        return false;
                    }

                    if (!pubAreaEccUnique.Y.AsSpan().SequenceEqual(authDataEc2.Y.AsSpan()))
                    {
                        return false;
                    }

                    return true;
                }
            default:
                return false;
        }

        static bool TryGetExponent(byte[] coseExp, [NotNullWhen(true)] out uint? exponent)
        {
            if (coseExp.Length > 4)
            {
                exponent = null;
                return false;
            }

            var bytesToAppend = 4 - coseExp.Length;
            if (bytesToAppend == 0)
            {
                exponent = BinaryPrimitives.ReadUInt32BigEndian(coseExp);
                return true;
            }

            Span<byte> coseBigEndianBuffer = stackalloc byte[4];
            for (var i = 0; i < 4; i++)
            {
                coseBigEndianBuffer[i] = 0;
            }

            coseExp.AsSpan().CopyTo(coseBigEndianBuffer[bytesToAppend..]);
            exponent = BinaryPrimitives.ReadUInt32BigEndian(coseBigEndianBuffer);
            return true;
        }

        static bool TryCoseEllipticCurveToTpm(CoseEllipticCurve crv, [NotNullWhen(true)] out TpmiEccCurve? tpmiEccCurve)
        {
            switch (crv)
            {
                case CoseEllipticCurve.P256:
                    {
                        tpmiEccCurve = TpmiEccCurve.TPM_ECC_NIST_P256;
                        return true;
                    }
                case CoseEllipticCurve.P384:
                    {
                        tpmiEccCurve = TpmiEccCurve.TPM_ECC_NIST_P384;
                        return true;
                    }
                case CoseEllipticCurve.P521:
                    {
                        tpmiEccCurve = TpmiEccCurve.TPM_ECC_NIST_P521;
                        return true;
                    }
                default:
                    {
                        tpmiEccCurve = null;
                        return false;
                    }
            }
        }
    }

    private static bool IsCertInfoValid(byte[] certInfo)
    {
        return false;
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
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

    /// <summary>
    ///     The TPMT_PUBLIC structure (see [TPMv2-Part2] section 12.2.4) used by the TPM to represent the credential public key.
    /// </summary>
    private class PubArea
    {
        private PubArea(
            TpmAlgPublic type,
            TpmAlgIdHash nameAlg,
            ObjectAttributes objectAttributes,
            AbstractPublicParms parameters,
            AbstractUnique unique)
        {
            Type = type;
            NameAlg = nameAlg;
            ObjectAttributes = objectAttributes;
            Parameters = parameters;
            Unique = unique;
        }

        public TpmAlgPublic Type { get; }

        public TpmAlgIdHash NameAlg { get; }

        public ObjectAttributes ObjectAttributes { get; }

        public AbstractPublicParms Parameters { get; }

        public AbstractUnique Unique { get; }

        public static bool TryParse(Span<byte> bytes, [NotNullWhen(true)] out PubArea? pubArea)
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
                pubArea = null;
                return false;
            }

            var type = (TpmAlgPublic) BinaryPrimitives.ReadUInt16BigEndian(rawType);
            if (!Enum.IsDefined(type))
            {
                pubArea = null;
                return false;
            }

            // nameAlg
            if (!TryConsume(ref buffer, 2, out var rawNameAlg))
            {
                pubArea = null;
                return false;
            }

            var nameAlg = (TpmAlgIdHash) BinaryPrimitives.ReadUInt16BigEndian(rawNameAlg);
            if (!Enum.IsDefined(nameAlg))
            {
                pubArea = null;
                return false;
            }

            // objectAttributes
            if (!TryConsume(ref buffer, 4, out var rawObjectAttributes))
            {
                pubArea = null;
                return false;
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
                pubArea = null;
                return false;
            }

            var authPolicySize = BinaryPrimitives.ReadUInt16BigEndian(rawAuthPolicySize);
            if (authPolicySize > 0)
            {
                if (!TryConsume(ref buffer, authPolicySize, out _))
                {
                    pubArea = null;
                    return false;
                }
            }

            // [type]parameters
            if (!AbstractPublicParms.TryParse(ref buffer, type, objectAttributes, out var parameters))
            {
                pubArea = null;
                return false;
            }

            //[type]unique
            if (!AbstractUnique.TryParse(ref buffer, type, out var unique))
            {
                pubArea = null;
                return false;
            }

            if (buffer.Length > 0)
            {
                pubArea = null;
                return false;
            }

            pubArea = new(type, nameAlg, objectAttributes, parameters, unique);
            return true;
        }
    }

    /// <summary>
    ///     12.2.3.4 TPMS_ASYM_PARMS
    /// </summary>
    private abstract class AbstractPublicParms
    {
        public static bool TryParse(
            ref Span<byte> buffer,
            TpmAlgPublic type,
            ObjectAttributes objectAttributes,
            [NotNullWhen(true)] out AbstractPublicParms? parameters)
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
                        if (RsaParms.TryParseRsaParms(ref buffer, objectAttributes, out var rsaParms))
                        {
                            parameters = rsaParms;
                            return true;
                        }

                        parameters = null;
                        return false;
                    }
                case TpmAlgPublic.Ecc:
                    {
                        if (EccParms.TryParseEccParms(ref buffer, objectAttributes, out var eccParms))
                        {
                            parameters = eccParms;
                            return true;
                        }

                        parameters = null;
                        return false;
                    }
                default:
                    {
                        parameters = null;
                        return false;
                    }
            }
        }
    }

    /// <summary>
    ///     12.2.3.5 TPMS_RSA_PARMS
    /// </summary>
    private class RsaParms : AbstractPublicParms
    {
        private RsaParms(ushort keyBits, uint exponent)
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
            // Table 195 — Definition of TPMS_ASYM_PARMS Structure <>
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
            if (scheme != TpmiAlgRsaScheme.TPM_ALG_NULL)
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
    }

    /// <summary>
    ///     12.2.3.6 TPMS_ECC_PARMS
    /// </summary>
    private class EccParms : AbstractPublicParms
    {
        private EccParms(TpmiEccCurve curveId)
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
            if (scheme != TpmiAlgEccScheme.TPM_ALG_NULL)
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
            if (kdfScheme != TpmiAlgKdf.TPM_ALG_NULL)
            {
                eccDetail = null;
                return false;
            }

            //[scheme]details is ignored if the scheme is TPM_ALG_NULL
            eccDetail = new(curveId);
            return true;
        }
    }


    /// <summary>
    ///     12.2.3.2 TPMU_PUBLIC_ID
    /// </summary>
    private abstract class AbstractUnique
    {
        public static bool TryParse(
            ref Span<byte> buffer,
            TpmAlgPublic type,
            [NotNullWhen(true)] out AbstractUnique? unique)
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
                        if (RsaUnique.TryParseRsaUnique(ref buffer, out var rsaUnique))
                        {
                            unique = rsaUnique;
                            return true;
                        }

                        unique = null;
                        return false;
                    }
                case TpmAlgPublic.Ecc:
                    {
                        if (EccUnique.TryParseEccUnique(ref buffer, out var eccUnique))
                        {
                            unique = eccUnique;
                            return true;
                        }

                        unique = null;
                        return false;
                    }
                default:
                    {
                        unique = null;
                        return false;
                    }
            }
        }
    }

    /// <summary>
    ///     11.2.4.5 TPM2B_PUBLIC_KEY_RSA
    /// </summary>
    private class RsaUnique : AbstractUnique
    {
        private RsaUnique(byte[] buffer)
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
    }

    /// <summary>
    ///     11.2.5.2 TPMS_ECC_POINT
    /// </summary>
    private class EccUnique : AbstractUnique
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
    }

    /// <summary>
    ///     TPMI_ALG_PUBLIC, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.o
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>12.2.2 TPMI_ALG_PUBLIC</para>
    /// </remarks>
    private enum TpmAlgPublic : ushort
    {
        // 12.2.2 TPMI_ALG_PUBLIC
        // Table 192 — Definition of (TPM_ALG_ID) TPMI_ALG_PUBLIC Type
        // | Values         | Comments
        // | TPM_ALG_!ALG.o | All object types
        // | #TPM_RC_TYPE   | response code when a public type is not supported

        /// <summary>
        ///     The RSA algorithm (TPM_ALG_RSA)
        /// </summary>
        /// <remarks>IETF RFC 8017</remarks>
        Rsa = 0x0001,

        /// <summary>
        ///     Prime field ECC (TPM_ALG_ECC)
        /// </summary>
        /// <remarks>ISO/IEC 15946-1</remarks>
        Ecc = 0x0023
    }

    /// <summary>
    ///     TPMI_ALG_SYM_OBJECT, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.S, +TPM_ALG_NULL
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>9.30 TPMI_ALG_SYM_OBJECT</para>
    /// </remarks>
    private enum TpmiAlgSymObject : ushort
    {
        // 9.30 TPMI_ALG_SYM_OBJECT
        // Table 68 — Definition of (TPM_ALG_ID) TPMI_ALG_SYM_OBJECT Type
        // | Values         | Comments
        // | TPM_ALG_!ALG.S | all symmetric block ciphers
        // | +TPM_ALG_NULL  | required to be present in all versions of this table

        /// <summary>
        ///     Null algorithm
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TpmAlgNull = 0x0010
    }

    /// <summary>
    ///     TPMI_ALG_HASH, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.H, +TPM_ALG_NULL
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>9.27 TPMI_ALG_HASH</para>
    /// </remarks>
    private enum TpmAlgIdHash : ushort
    {
        // 9.27 TPMI_ALG_HASH
        // A TPMI_ALG_HASH is an interface type of all the hash algorithms implemented on a specific TPM.
        // Table 65 — Definition of (TPM_ALG_ID) TPMI_ALG_HASH Type
        // | Values         | Comments
        // | TPM_ALG_!ALG.H | All hash algorithms defined by the TCG
        // | +TPM_ALG_NULL  |

        /// <summary>
        ///     The SHA1 algorithm (TPM_ALG_SHA1)
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        Sha1 = 0x0004,

        /// <summary>
        ///     The SHA 256 algorithm (TPM_ALG_SHA256)
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        Sha256 = 0x000B,

        /// <summary>
        ///     The SHA 384 algorithm (TPM_ALG_SHA384)
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        Sha384 = 0x000C,

        /// <summary>
        ///     The SHA 512 algorithm (TPM_ALG_SHA512)
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        Sha512 = 0x000D
    }

    /// <summary>
    ///     TPMA_OBJECT (UINT32) - Object Attributes
    ///     <para>
    ///         This attribute structure indicates an object’s use, its authorization types, and its relationship to other objects.
    ///         The state of the attributes is determined when the object is created and they are never changed by the TPM.
    ///     </para>
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>8.3 TPMA_OBJECT (Object Attributes)</para>
    /// </remarks>
    [Flags]
    private enum ObjectAttributes : uint
    {
        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>The hierarchy of the object, as indicated by its Qualified Name, may not change.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>The hierarchy of the object may change as a result of this object or an ancestor key being duplicated for use in another hierarchy.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        /// <remarks>
        ///     Note: fixedTPM does not indicate that key material resides on a single TPM (see sensitiveDataOrigin).
        /// </remarks>
        FixedTpm = 1 << 1,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>Previously saved contexts of this object may not be loaded after Startup(CLEAR).</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>Saved contexts of this object may be used after a Shutdown(STATE) and subsequent Startup().</description>
        ///         </item>
        ///     </list>
        /// </summary>
        StClear = 1 << 2,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>The parent of the object may not change.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>The parent of the object may change as the result of a TPM2_Duplicate() of the object.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        FixedParent = 1 << 4,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>Indicates that, when the object was created with TPM2_Create() or TPM2_CreatePrimary(), the TPM generated all of the sensitive data other than the authValue.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>A portion of the sensitive data, other than the authValue, was provided by the caller.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        SensitiveDataOrigin = 1 << 5,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>Approval of USER role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>Approval of USER role actions with this object may only be done with a policy session.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        UserWithAuth = 1 << 6,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>Approval of ADMIN role actions with this object may only be done with a policy session.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>Approval of ADMIN role actions with this object may be with an HMAC session or with a password using the authValue of the object or a policy session.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        AdminWithPolicy = 1 << 7,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>The object is not subject to dictionary attack protections.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>The object is subject to dictionary attack protections.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        NoDa = 1 << 10,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>If the object is duplicated, then symmetricAlg shall not be TPM_ALG_NULL and newParentHandle shall not be TPM_RH_NULL.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>The object may be duplicated without an inner wrapper on the private portion of the object and the new parent may be TPM_RH_NULL.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        EncryptedDuplication = 1 << 11,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>Key usage is restricted to manipulate structures of known format; the parent of this key shall have restricted SET.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>Key usage is not restricted to use on special formats.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        Restricted = 1 << 16,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>The private portion of the key may be used to decrypt.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>The private portion of the key may not be used to decrypt.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        Decrypt = 1 << 17,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>For a symmetric cipher object, the private portion of the key may be used to encrypt. For other objects, the private portion of the key may be used to sign.</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>The private portion of the key may not be used to sign or encrypt.</description>
        ///         </item>
        ///     </list>
        /// </summary>
        SignEncrypt = 1 << 18,

        /// <summary>
        ///     <list type="table">
        ///         <item>
        ///             <term>
        ///                 <see langword="true" />
        ///             </term>
        ///             <description>An asymmetric key that may not be used to sign with TPM2_Sign().</description>
        ///         </item>
        ///         <item>
        ///             <term>
        ///                 <see langword="false" />
        ///             </term>
        ///             <description>: A key that may be used with TPM2_Sign() if sign is SET</description>
        ///         </item>
        ///     </list>
        /// </summary>
        /// <remarks>
        ///     Note: This attribute only has significance if sign is SET.
        /// </remarks>
        X509Sign = 1 << 19
    }

    /// <summary>
    ///     TPMI_ALG_RSA_SCHEME, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.ae.ax, +TPM_ALG_NULL
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>11.2.4.1 TPMI_ALG_RSA_SCHEME</para>
    /// </remarks>
    private enum TpmiAlgRsaScheme : ushort
    {
        /// <summary>
        ///     Null algorithm
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_NULL = 0x0010

        // /// <summary>
        // ///     A signature algorithm defined in section 8.2 (RSASSAPKCS1-v1_5)
        // /// </summary>
        // /// <remarks>IETF RFC 8017</remarks>
        // TPM_ALG_RSASSA = 0x0014,
        //
        // /// <summary>
        // ///     A signature algorithm definedin section 8.1 (RSASSA-PSS)
        // /// </summary>
        // /// <remarks>IETF RFC 8017</remarks>
        // TPM_ALG_RSAPSS = 0x0016,
    }

    /// <summary>
    ///     TPMI_ALG_ECC_SCHEME, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.ax,TPM_ALG_!ALG.am, +TPM_ALG_NULL
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>11.2.5.4 TPMI_ALG_ECC_SCHEME</para>
    /// </remarks>
    private enum TpmiAlgEccScheme : ushort
    {
        /// <summary>
        ///     Null algorithm
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_NULL = 0x0010

        // /// <summary>
        // ///     A signature algorithm defined in section 8.2 (RSASSAPKCS1-v1_5)
        // /// </summary>
        // /// <remarks>IETF RFC 8017</remarks>
        // TPM_ALG_RSASSA = 0x0014,
        //
        // /// <summary>
        // ///     A signature algorithm definedin section 8.1 (RSASSA-PSS)
        // /// </summary>
        // /// <remarks>IETF RFC 8017</remarks>
        // TPM_ALG_RSAPSS = 0x0016,
    }

    /// <summary>
    ///     TPMI_ECC_CURVE, based on TPM_ECC_CURVE (UINT16).
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>11.2.5.5 TPMI_ECC_CURVE</para>
    /// </remarks>
    private enum TpmiEccCurve : ushort
    {
        /// <summary>
        ///     TPM_ECC_NONE
        /// </summary>
        TPM_ECC_NONE = 0x0000,

        /// <summary>
        ///     TPM_ECC_NIST_P256
        /// </summary>
        TPM_ECC_NIST_P256 = 0x0003,

        /// <summary>
        ///     TPM_ECC_NIST_P384
        /// </summary>
        TPM_ECC_NIST_P384 = 0x0004,

        /// <summary>
        ///     TPM_ECC_NIST_P521
        /// </summary>
        TPM_ECC_NIST_P521 = 0x0005
    }


    /// <summary>
    ///     TPMI_ALG_KDF, based on TPM_ALG_ID (UINT16) - TPM_ALG_!ALG.HM, +TPM_ALG_NULL
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>9.32 TPMI_ALG_KDF (Key and Mask Generation Functions)</para>
    /// </remarks>
    private enum TpmiAlgKdf : ushort
    {
        /// <summary>
        ///     Null algorithm
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_NULL = 0x0010
    }
    //

    /// <summary>
    ///     TPM_ALG_ID
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
    ///     </para>
    ///     <para>
    ///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
    ///     </para>
    ///     <para>6.3 TPM_ALG_ID</para>
    /// </remarks>
    private enum TPM_ALG_ID : ushort
    {
        /// <summary>
        ///     Should not occur
        /// </summary>
        TPM_ALG_ERROR = 0x0000,

        /// <summary>
        ///     The RSA algorithm
        /// </summary>
        /// <remarks>IETF RFC 8017</remarks>
        TPM_ALG_RSA = 0x0001,

        /// <summary>
        ///     Block cipher with various key sizes (Triple Data Encryption Algorithm, commonly called Triple Data Encryption Standard)
        /// </summary>
        /// <remarks>ISO/IEC 18033-3</remarks>
        TPM_ALG_TDES = 0x0003,

        /// <summary>
        ///     The SHA1 algorithm
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        TPM_ALG_SHA1 = 0x0004,

        /// <summary>
        ///     Hash Message Authentication Code (HMAC) algorithm
        /// </summary>
        /// <remarks>ISO/IEC 9797-2</remarks>
        TPM_ALG_HMAC = 0x0005,

        /// <summary>
        ///     The AES algorithm with various key sizes
        /// </summary>
        /// <remarks>ISO/IEC 18033-3</remarks>
        TPM_ALG_AES = 0x0006,

        /// <summary>
        ///     Hash-based mask-generation function
        /// </summary>
        /// <remarks>
        ///     <para>IEEE Std 1363 (TM) - 2000</para>
        ///     <para>IEEE Std 1363a (TM) - 2004</para>
        /// </remarks>
        TPM_ALG_MGF1 = 0x0007,

        /// <summary>
        ///     An object type that may use XOR for encryption or an HMAC for signing and may also refer to a data object that is neither signing nor encrypting
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_KEYEDHASH = 0x0008,

        /// <summary>
        ///     The XOR encryption algorithm
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_XOR = 0x000A,

        /// <summary>
        ///     The SHA 256 algorithm
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        TPM_ALG_SHA256 = 0x000B,

        /// <summary>
        ///     The SHA 384 algorithm
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        TPM_ALG_SHA384 = 0x000C,

        /// <summary>
        ///     The SHA 512 algorithm
        /// </summary>
        /// <remarks>ISO/IEC 10118-3</remarks>
        TPM_ALG_SHA512 = 0x000D,

        /// <summary>
        ///     Null algorithm
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_NULL = 0x0010,

        /// <summary>
        ///     SM3 hash algorithm
        /// </summary>
        /// <remarks>GM/T 0004-2012</remarks>
        TPM_ALG_SM3_256 = 0x0012,

        /// <summary>
        ///     SM4 symmetric block cipher
        /// </summary>
        /// <remarks>GM/T 0002-2012</remarks>
        TPM_ALG_SM4 = 0x0013,

        /// <summary>
        ///     A signature algorithm defined in section 8.2 (RSASSAPKCS1-v1_5)
        /// </summary>
        /// <remarks>IETF RFC 8017</remarks>
        TPM_ALG_RSASSA = 0x0014,

        /// <summary>
        ///     A padding algorithm defined in section 7.2 (RSAESPKCS1-v1_5)
        /// </summary>
        /// <remarks>IETF RFC 8017</remarks>
        TPM_ALG_RSAES = 0x0015,

        /// <summary>
        ///     A signature algorithm definedin section 8.1 (RSASSA-PSS)
        /// </summary>
        /// <remarks>IETF RFC 8017</remarks>
        TPM_ALG_RSAPSS = 0x0016,

        /// <summary>
        ///     A padding algorithm defined in section 7.1 (RSAES_OAEP)
        /// </summary>
        /// <remarks>IETF RFC 8017</remarks>
        TPM_ALG_OAEP = 0x0017,

        /// <summary>
        ///     Signature algorithm using elliptic curve cryptography (ECC)
        /// </summary>
        /// <remarks>ISO/IEC 14888-3</remarks>
        TPM_ALG_ECDSA = 0x0018,

        /// <summary>
        ///     Secret sharing using ECC. Based on context, this can be either One-Pass DiffieHellman, C(1, 1, ECC CDH) defined in 6.2.2.2
        ///     or Full Unified Model C(2, 2, ECC CDH) defined in 6.1.1.2
        /// </summary>
        /// <remarks>NIST SP800-56A</remarks>
        TPM_ALG_ECDH = 0x0019,

        /// <summary>
        ///     Elliptic-curve based, anonymous signing scheme
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_ECDAA = 0x001A,

        /// <summary>
        ///     SM2 – depending on context, either an elliptic-curve based, signature algorithm or a key exchange protocol
        ///     <para>NOTE: Type listed as signing but, other uses are allowed according to context.</para>
        /// </summary>
        /// <remarks>
        ///     <para>GM/T 0003.1–2012</para>
        ///     <para>GM/T 0003.2–2012</para>
        ///     <para>GM/T 0003.3–2012</para>
        ///     <para>GM/T 0003.5–2012</para>
        /// </remarks>
        TPM_ALG_SM2 = 0x001B,

        /// <summary>
        ///     Elliptic-curve based Schnorr signature
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_ECSCHNORR = 0x001C,

        /// <summary>
        ///     Two-phase elliptic-curve key exchange – C(2, 2, ECC MQV) section 6.1.1.4
        /// </summary>
        /// <remarks>NIST SP800-56A</remarks>
        TPM_ALG_ECMQV = 0x001D,

        /// <summary>
        ///     Concatenation key derivation function (approved alternative 1) section 5.8.1
        /// </summary>
        /// <remarks>NIST SP800-56A</remarks>
        TPM_ALG_KDF1_SP800_56A = 0x0020,

        /// <summary>
        ///     Key derivation function KDF2 section 13.2
        /// </summary>
        /// <remarks>IEEE Std 1363a-2004</remarks>
        TPM_ALG_KDF2 = 0x0021,

        /// <summary>
        ///     A key derivation method Section 5.1 KDF in Counter Mode
        /// </summary>
        /// <remarks>NIST SP800-108</remarks>
        TPM_ALG_KDF1_SP800_108 = 0x0022,

        /// <summary>
        ///     Prime field ECC
        /// </summary>
        /// <remarks>ISO/IEC 15946-1</remarks>
        TPM_ALG_ECC = 0x0023,

        /// <summary>
        ///     The object type for a symmetric block cipher
        /// </summary>
        /// <remarks>TCG TPM 2.0 library specification</remarks>
        TPM_ALG_SYMCIPHER = 0x0025,

        /// <summary>
        ///     Camellia is symmetric block cipher. The Camellia algorithm with various key sizes
        /// </summary>
        /// <remarks>ISO/IEC 18033-3</remarks>
        TPM_ALG_CAMELLIA = 0x0026,

        /// <summary>
        ///     Hash algorithm producing a 256-bit digest
        /// </summary>
        /// <remarks>NIST PUB FIPS 202</remarks>
        TPM_ALG_SHA3_256 = 0x0027,

        /// <summary>
        ///     Hash algorithm producing a 384-bit digest
        /// </summary>
        /// <remarks>NIST PUB FIPS 202</remarks>
        TPM_ALG_SHA3_384 = 0x0028,

        /// <summary>
        ///     Hash algorithm producing a 512-bit digest
        /// </summary>
        /// <remarks>NIST PUB FIPS 202</remarks>
        TPM_ALG_SHA3_512 = 0x0029,

        /// <summary>
        ///     Counter mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        /// <remarks>ISO/IEC 10116</remarks>
        TPM_ALG_CTR = 0x0040,

        /// <summary>
        ///     Output Feedback mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        /// <remarks>ISO/IEC 10116</remarks>
        TPM_ALG_OFB = 0x0041,

        /// <summary>
        ///     Cipher Block Chaining mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        /// <remarks>ISO/IEC 10116</remarks>
        TPM_ALG_CBC = 0x0042,

        /// <summary>
        ///     Cipher Feedback mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        /// </summary>
        /// <remarks>ISO/IEC 10116</remarks>
        TPM_ALG_CFB = 0x0043,

        /// <summary>
        ///     Electronic Codebook mode – if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
        ///     <para>NOTE: This mode is not recommended for uses unless the key is frequently rotated such as in video codecs</para>
        /// </summary>
        /// <remarks>ISO/IEC 10116</remarks>
        TPM_ALG_ECB = 0x0044
    }
}
