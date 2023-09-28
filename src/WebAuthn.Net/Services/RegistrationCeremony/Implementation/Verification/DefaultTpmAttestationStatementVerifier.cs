using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.Extensions;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.RegistrationCeremony.Verification;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification;

public class DefaultTpmAttestationStatementVerifier : ITpmAttestationStatementVerifier
{
    private readonly IDigitalSignatureVerifier _signatureVerifier;
    private readonly ITimeProvider _timeProvider;

    public DefaultTpmAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IDigitalSignatureVerifier signatureVerifier)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(signatureVerifier);
        _timeProvider = timeProvider;
        _signatureVerifier = signatureVerifier;
    }

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
        if (!IsCertInfoValid(attStmt, attToBeSigned))
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

    private bool IsCertInfoValid(
        TpmAttestationStatement attStmt,
        byte[] attToBeSigned)
    {
        // Validate that certInfo is valid:
        // 1) Verify that magic is set to TPM_GENERATED_VALUE.
        // Handled in CertInfo.TryParse
        // 2) Verify that type is set to TPM_ST_ATTEST_CERTIFY.
        // Handled in CertInfo.TryParse
        if (!CertInfo.TryParse(attStmt.CertInfo, out var certInfo))
        {
            return false;
        }

        // 3) Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
        if (!attStmt.Alg.TryComputeHash(attToBeSigned, out var attToBeSignedHash))
        {
            return false;
        }

        if (!certInfo.ExtraData.AsSpan().SequenceEqual(attToBeSignedHash.AsSpan()))
        {
            return false;
        }

        // 4) Verify that 'attested' contains a TPMS_CERTIFY_INFO structure as specified in [TPMv2-Part2] section 10.12.3,
        // whose 'name' field contains a valid 'Name' for 'pubArea',
        // as computed using the algorithm in the nameAlg field of pubArea using the procedure specified in [TPMv2-Part1] section 16.
        if (certInfo.Attested.Name.Digest is null)
        {
            return false;
        }

        var nameAlg = certInfo.Attested.Name.Digest.HashAlg;
        var attestedNameHash = certInfo.Attested.Name.Digest.Digest;
        if (!TryComputeHash(nameAlg, attStmt.PubArea, out var pubAreaHash))
        {
            return false;
        }

        if (!pubAreaHash.AsSpan().SequenceEqual(attestedNameHash.AsSpan()))
        {
            return false;
        }

        // 5) Note that the remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2,
        // i.e., qualifiedSigner, clockInfo and firmwareVersion are ignored. These fields MAY be used as an input to risk engines.

        // 6) Verify that x5c is present.
        if (attStmt.X5C.Length < 1)
        {
            return false;
        }

        var trustPath = new X509Certificate2[attStmt.X5C.Length];
        for (var i = 0; i < trustPath.Length; i++)
        {
            var x5CCert = new X509Certificate2(attStmt.X5C[i]);
            var currentDate = _timeProvider.GetUtcDateTime();
            if (currentDate < x5CCert.NotBefore || currentDate > x5CCert.NotAfter)
            {
                return false;
            }

            trustPath[i] = x5CCert;
        }

        var aikCert = trustPath.First();
        // 7) Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
        if (!_signatureVerifier.IsValidCertificateSign(aikCert, attStmt.Alg, attStmt.CertInfo, attStmt.Sig))
        {
            return false;
        }
        // 8) Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.

        return false;

        [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms")]
        static bool TryComputeHash(TpmAlgIdHash tpmAlg, byte[] message, [NotNullWhen(true)] out byte[]? hash)
        {
            switch (tpmAlg)
            {
                case TpmAlgIdHash.Sha1:
                    {
                        hash = SHA1.HashData(message);
                        return true;
                    }
                case TpmAlgIdHash.Sha256:
                    {
                        hash = SHA256.HashData(message);
                        return true;
                    }
                case TpmAlgIdHash.Sha384:
                    {
                        hash = SHA384.HashData(message);
                        return true;
                    }
                case TpmAlgIdHash.Sha512:
                    {
                        hash = SHA512.HashData(message);
                        return true;
                    }
                default:
                    {
                        hash = null;
                        return false;
                    }
            }
        }
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
    ///     The TPMS_ATTEST structure over which the above signature was computed, as specified in [TPMv2-Part2] section 10.12.8.
    /// </summary>
    private class CertInfo
    {
        public CertInfo(
            Tpm2BName qualifiedSigner,
            byte[] extraData,
            ulong clock,
            uint resetCount,
            uint restartCount,
            bool safe,
            ulong firmwareVersion,
            Attested attested)
        {
            QualifiedSigner = qualifiedSigner;
            ExtraData = extraData;
            Clock = clock;
            ResetCount = resetCount;
            RestartCount = restartCount;
            Safe = safe;
            FirmwareVersion = firmwareVersion;
            Attested = attested;
        }

        public Tpm2BName QualifiedSigner { get; }
        public byte[] ExtraData { get; }
        public ulong Clock { get; }
        public uint ResetCount { get; }
        public uint RestartCount { get; }
        public bool Safe { get; }
        public ulong FirmwareVersion { get; }
        public Attested Attested { get; }


        public static bool TryParse(Span<byte> bytes, [NotNullWhen(true)] out CertInfo? certInfo)
        {
            var buffer = bytes;
            // 10.12.12 TPMS_ATTEST
            // This structure is used on each TPM-generated signed structure.
            // The signature is over this structure.
            // When the structure is signed by a key in the Storage hierarchy, the values of clockInfo.resetCount, clockInfo.restartCount, and firmwareVersion are obfuscated with a per-key obfuscation value.
            // Table 132 — Definition of TPMS_ATTEST Structure <OUT>
            // | Parameter       | Type            | Description
            // | magic           | TPM_GENERATED   | The indication that this structure was created by a TPM (always TPM_GENERATED_VALUE)
            // | type            | TPMI_ST_ATTEST  | Type of the attestation structure
            // | qualifiedSigner | TPM2B_NAME      | Qualified Name of the signing key
            // | extraData       | TPM2B_DATA      | External information supplied by caller.
            // |                 |                 |   NOTE: A TPM2B_DATA structure provides room for a digest and a method indicator to indicate the components of the digest.
            // |                 |                 |         The definition of this method indicator is outside the scope of this specification.
            // | clockInfo       | TPMS_CLOCK_INFO | Clock, resetCount, restartCount, and Safe
            // | firmwareVersion | UINT64          | TPM-vendor-specific value identifying the version number of the firmware
            // | [type]attested  | TPMU_ATTEST     | The type-specific attestation information

            // magic
            // 6.2 TPM_GENERATED
            // This constant value differentiates TPM-generated structures from non-TPM structures.
            // Table 7 — Definition of (UINT32) TPM_GENERATED Constants <O>
            // | Name                | Value      | Comments
            // | TPM_GENERATED_VALUE | 0xff544347 | 0xFF 'TCG' (FF 54 43 47)
            if (!TryConsume(ref buffer, 4, out var rawMagic))
            {
                certInfo = null;
                return false;
            }

            var magic = BinaryPrimitives.ReadUInt32BigEndian(rawMagic);
            // Validate that certInfo is valid:
            // 1) Verify that magic is set to TPM_GENERATED_VALUE.
            if (magic != 0xff544347)
            {
                certInfo = null;
                return false;
            }

            // type
            // According to the WebAuthn specification, only TPM_ST_ATTEST_CERTIFY is allowed
            // 10.12.10 TPMI_ST_ATTEST
            // Table 130 — Definition of (TPM_ST) TPMI_ST_ATTEST Type <OUT>
            // | Value                       | Description
            // | TPM_ST_ATTEST_CERTIFY       | generated by TPM2_Certify()
            // | TPM_ST_ATTEST_QUOTE         | generated by TPM2_Quote()
            // | TPM_ST_ATTEST_SESSION_AUDIT | generated by TPM2_GetSessionAuditDigest()
            // | TPM_ST_ATTEST_COMMAND_AUDIT | generated by TPM2_GetCommandAuditDigest()
            // | TPM_ST_ATTEST_TIME          | generated by TPM2_GetTime()
            // | TPM_ST_ATTEST_CREATION      | generated by TPM2_CertifyCreation()
            // | TPM_ST_ATTEST_NV            | generated by TPM2_NV_Certify()
            // | TPM_ST_ATTEST_NV_DIGEST     | generated by TPM2_NV_Certify()
            // 6.9 TPM_ST (Structure Tags)
            // Table 19 — Definition of (UINT16) TPM_ST Constants <IN/OUT, S>
            // | Name                  | Value  | Comments
            // | TPM_ST_ATTEST_CERTIFY | 0x8017 | Tag for an attestation structure
            if (!TryConsume(ref buffer, 2, out var rawType))
            {
                certInfo = null;
                return false;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(rawType);
            // Validate that certInfo is valid:
            // 2) Verify that type is set to TPM_ST_ATTEST_CERTIFY.
            if (type != 0x8017)
            {
                certInfo = null;
                return false;
            }

            // qualifiedSigner
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
            if (!Tpm2BName.TryParse(ref buffer, out var qualifiedSigner))
            {
                certInfo = null;
                return false;
            }

            // extraData
            // 10.4.3 TPM2B_DATA
            // This structure is used for a data buffer that is required to be no larger than the size of the Name of an object.
            // Table 81 — Definition of TPM2B_DATA Structure
            // | Name                           | Type   | Description
            // | size                           | UINT16 | size in octets of the buffer field; may be 0
            // | buffer[size]{:sizeof(TPMT_HA)} | BYTE   |
            if (!TryConsume(ref buffer, 2, out var rawExtraDataSize))
            {
                certInfo = null;
                return false;
            }

            // extraData.size
            var extraDataSize = BinaryPrimitives.ReadUInt16BigEndian(rawExtraDataSize);
            var extraData = new byte[extraDataSize];
            // extraData.buffer
            if (extraDataSize > 0)
            {
                if (!TryConsume(ref buffer, extraDataSize, out var rawExtraData))
                {
                    certInfo = null;
                    return false;
                }

                if (!rawExtraData.TryCopyTo(extraData.AsSpan()))
                {
                    certInfo = null;
                    return false;
                }
            }

            // clockInfo
            // 10.11.1 TPMS_CLOCK_INFO
            // This structure is used in each of the attestation commands.
            // Table 120 — Definition of TPMS_CLOCK_INFO Structure
            // | Name         | Type        | Description
            // | clock        | UINT64      | Time value in milliseconds that advances while the TPM is powered
            // |              |             |   NOTE: The interpretation of the time-origin (clock=0) is out of the scope of this specification,
            // |              |             |         although Coordinated Universal Time (UTC) is expected to be a common convention.
            // |              |             |         This structure element is used to report on the TPM's Clock value.
            // |              |             | This value is reset to zero when the Storage Primary Seed is changed (TPM2_Clear()).
            // |              |             | This value may be advanced by TPM2_ClockSet().
            // | resetCount   | UINT32      | Number of occurrences of TPM Reset since the last TPM2_Clear()
            // | restartCount | UINT32      | Number of times that TPM2_Shutdown() or _TPM_Hash_Start have occurred since the last TPM Reset or TPM2_Clear().
            // | safe         | TPMI_YES_NO | No value of Clock greater than the current value of Clock has been previously reported by the TPM. Set to YES on TPM2_Clear().

            // clockInfo.clock
            if (!TryConsume(ref buffer, 8, out var rawClockInfoClock))
            {
                certInfo = null;
                return false;
            }

            var clockInfoClock = BinaryPrimitives.ReadUInt64BigEndian(rawClockInfoClock);

            // clockInfo.resetCount
            if (!TryConsume(ref buffer, 4, out var rawClockInfoResetCount))
            {
                certInfo = null;
                return false;
            }

            var clockInfoResetCount = BinaryPrimitives.ReadUInt32BigEndian(rawClockInfoResetCount);

            // clockInfo.restartCount
            if (!TryConsume(ref buffer, 4, out var rawClockInfoRestartCount))
            {
                certInfo = null;
                return false;
            }

            var clockInfoRestartCount = BinaryPrimitives.ReadUInt32BigEndian(rawClockInfoRestartCount);

            // clockInfo.safe
            // 9.2 TPMI_YES_NO
            // This interface type is used in place of a Boolean type in order to eliminate ambiguity in the handling of a octet that conveys a single bit of information.
            // This type only has two allowed values, YES (1) and NO (0).
            // Table 40 — Definition of (BYTE) TPMI_YES_NO Type
            // | Value | Description
            // | NO    | a value of 0
            // | YES   | a value of 1
            if (!TryConsume(ref buffer, 1, out var rawClockInfoSafe))
            {
                certInfo = null;
                return false;
            }

            bool clockInfoSafe;
            switch (rawClockInfoSafe[0])
            {
                case 0:
                    clockInfoSafe = false;
                    break;
                case 1:
                    clockInfoSafe = true;
                    break;
                default:
                    certInfo = null;
                    return false;
            }

            // firmwareVersion UINT64
            if (!TryConsume(ref buffer, 8, out var rawFirmwareVersion))
            {
                certInfo = null;
                return false;
            }

            var firmwareVersion = BinaryPrimitives.ReadUInt64BigEndian(rawFirmwareVersion);

            // [type]attested
            // According to the WebAuthn specification, only TPM_ST_ATTEST_CERTIFY is allowed
            // 10.12.11 TPMU_ATTEST
            // Table 131 — Definition of TPMU_ATTEST Union <OUT>
            // | Parameter | Type              | Selector
            // | certify   | TPMS_CERTIFY_INFO | TPM_ST_ATTEST_CERTIFY
            // 10.12.3 TPMS_CERTIFY_INFO
            // This is the attested data for TPM2_Certify().
            // Table 123 — Definition of TPMS_CERTIFY_INFO Structure <OUT>
            // | Parameter     | Type       | Description
            // | name          | TPM2B_NAME | Name of the certified object
            // | qualifiedName | TPM2B_NAME | Qualified Name of the certified object
            if (!Tpm2BName.TryParse(ref buffer, out var attestedName))
            {
                certInfo = null;
                return false;
            }

            if (!Tpm2BName.TryParse(ref buffer, out var attestedQualifiedName))
            {
                certInfo = null;
                return false;
            }

            if (buffer.Length > 0)
            {
                certInfo = null;
                return false;
            }

            certInfo = new(
                qualifiedSigner,
                extraData,
                clockInfoClock,
                clockInfoResetCount,
                clockInfoRestartCount,
                clockInfoSafe,
                firmwareVersion,
                new(attestedName, attestedQualifiedName));
            return true;
        }
    }

    /// <summary>
    ///     10.12.3 TPMS_CERTIFY_INFO
    /// </summary>
    private class Attested
    {
        public Attested(Tpm2BName name, Tpm2BName qualifiedName)
        {
            Name = name;
            QualifiedName = qualifiedName;
        }

        // According to the WebAuthn specification, only TPM_ST_ATTEST_CERTIFY is allowed
        // 10.12.11 TPMU_ATTEST
        // Table 131 — Definition of TPMU_ATTEST Union <OUT>
        // | Parameter | Type              | Selector
        // | certify   | TPMS_CERTIFY_INFO | TPM_ST_ATTEST_CERTIFY
        // 10.12.3 TPMS_CERTIFY_INFO
        // This is the attested data for TPM2_Certify().
        // Table 123 — Definition of TPMS_CERTIFY_INFO Structure <OUT>
        // | Parameter     | Type       | Description
        // | name          | TPM2B_NAME | Name of the certified object
        // | qualifiedName | TPM2B_NAME | Qualified Name of the certified object

        public Tpm2BName Name { get; }

        public Tpm2BName QualifiedName { get; }
    }

    /// <summary>
    ///     10.5.3 TPM2B_NAME
    /// </summary>
    private class Tpm2BName
    {
        private Tpm2BName()
        {
            Digest = null;
            Handle = null;
        }

        private Tpm2BName(TpmtHa digest)
        {
            Digest = digest;
            Handle = null;
        }

        private Tpm2BName(TpmHandle handle)
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
    }

    /// <summary>
    ///     10.3.2 TPMT_HA
    /// </summary>
    private class TpmtHa
    {
        public TpmtHa(TpmAlgIdHash hashAlg, byte[] digest)
        {
            HashAlg = hashAlg;
            Digest = digest;
        }

        // 10.3.2 TPMT_HA
        // Table 79 shows the basic hash-agile structure used in this specification.
        // To handle hash agility, this structure uses the hashAlg parameter to indicate the algorithm used to compute the digest and,
        // by implication, the size of the digest.
        // Table 79 — Definition of TPMT_HA Structure <IN/OUT>
        // | Parameter        | Type           | Description
        // | hashAlg          | +TPMI_ALG_HASH | selector of the hash contained in the digest that implies the size of the digest
        // | [hashAlg] digest | TPMU_HA        | the digest data

        public TpmAlgIdHash HashAlg { get; }

        public byte[] Digest { get; }
    }

    /// <summary>
    ///     7.1 TPM_HANDLE
    /// </summary>
    private class TpmHandle
    {
        public TpmHandle(uint handle)
        {
            Handle = handle;
        }

        // 7 Handles
        // 7.1 Introduction
        // Handles are 32-bit values used to reference shielded locations of various types within the TPM.
        // Table 26 — Definition of Types for Handles
        // | Type   | Name       | Description
        // | UINT32 | TPM_HANDLE |

        public uint Handle { get; }
    }
}
