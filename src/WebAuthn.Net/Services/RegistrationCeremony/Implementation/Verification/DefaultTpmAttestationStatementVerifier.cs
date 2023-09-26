using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models;
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

        // 3 - Concatenate authenticatorData and clientDataHash to form attToBeSigned.
        var attToBeSigned = Concat(authData.RawAuthData, clientDataHash);

        // 4 - Validate that certInfo is valid
        if (!IsCertInfoValid())
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        throw new NotImplementedException();
    }

    private static bool IsCertInfoValid()
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
        public static bool TryParse(byte[] bytes, [NotNullWhen(true)] out PubArea? pubArea)
        {
            var buffer = bytes.AsSpan();

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

            var objectAttributesFlags = (ObjectAttributesFlags) BinaryPrimitives.ReadUInt32BigEndian(rawObjectAttributes);
            var objectAttributes = new ObjectAttributes(objectAttributesFlags);

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

            // build pub area depending on algorithm type
            switch (type)
            {
                case TpmAlgPublic.Rsa:
                    return TryParseRsa(buffer, nameAlg, objectAttributes, out pubArea);
                case TpmAlgPublic.Ecc:
                    return TryParseEcc(buffer, nameAlg, objectAttributes, out pubArea);
                default:
                    pubArea = null;
                    return false;
            }
        }

        private static bool TryParseRsa(
            Span<byte> buffer,
            TpmAlgIdHash nameAlg,
            ObjectAttributes objectAttributes,
            [NotNullWhen(true)] out PubArea? pubArea)
        {
            pubArea = null;
            return false;
        }

        private static bool TryParseEcc(
            Span<byte> buffer,
            TpmAlgIdHash nameAlg,
            ObjectAttributes objectAttributes,
            [NotNullWhen(true)] out PubArea? pubArea)
        {
            // 12.2.3.7 TPMU_PUBLIC_PARMS
            // Parse TPMS_ECC_PARMS based on type TPM_ALG_ECC

            //var type = TpmKeyAlgorithm.TPM_ALG_ECC;
            pubArea = null;
            return false;
        }
    }

    /// <summary>
    ///     TPMI_ALG_PUBLIC, based on TPM_ALG_ID (UINT16, Type O – an object type)
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
    ///     TPMI_ALG_HASH, based on TPM_ALG_ID (UINT16, Type H – hash algorithm that compresses input data to a digest value or indicates a method that uses a hash)
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
        // | #TPM_RC_HASH   |

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
    ///     TPMA_OBJECT (Object Attributes, UINT32).
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
    private enum ObjectAttributesFlags : uint
    {
        FixedTpm = 1 << 1,
        StClear = 1 << 2,
        FixedParent = 1 << 4,
        SensitiveDataOrigin = 1 << 5,
        UserWithAuth = 1 << 6,
        AdminWithPolicy = 1 << 7,
        NoDa = 1 << 10,
        EncryptedDuplication = 1 << 11,
        Restricted = 1 << 16,
        Decrypt = 1 << 17,
        SignEncrypt = 1 << 18,
        X509Sign = 1 << 19
    }

    /// <summary>
    ///     TPMA_OBJECT (Object Attributes, UINT32).
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
    private class ObjectAttributes
    {
        public ObjectAttributes(ObjectAttributesFlags flags)
        {
            FixedTpm = (flags & ObjectAttributesFlags.FixedTpm) == ObjectAttributesFlags.FixedTpm;
            StClear = (flags & ObjectAttributesFlags.StClear) == ObjectAttributesFlags.StClear;
            FixedParent = (flags & ObjectAttributesFlags.FixedParent) == ObjectAttributesFlags.FixedParent;
            SensitiveDataOrigin = (flags & ObjectAttributesFlags.SensitiveDataOrigin) == ObjectAttributesFlags.SensitiveDataOrigin;
            UserWithAuth = (flags & ObjectAttributesFlags.UserWithAuth) == ObjectAttributesFlags.UserWithAuth;
            AdminWithPolicy = (flags & ObjectAttributesFlags.AdminWithPolicy) == ObjectAttributesFlags.AdminWithPolicy;
            NoDa = (flags & ObjectAttributesFlags.NoDa) == ObjectAttributesFlags.NoDa;
            EncryptedDuplication = (flags & ObjectAttributesFlags.EncryptedDuplication) == ObjectAttributesFlags.EncryptedDuplication;
            Restricted = (flags & ObjectAttributesFlags.Restricted) == ObjectAttributesFlags.Restricted;
            Decrypt = (flags & ObjectAttributesFlags.Decrypt) == ObjectAttributesFlags.Decrypt;
            SignEncrypt = (flags & ObjectAttributesFlags.SignEncrypt) == ObjectAttributesFlags.SignEncrypt;
            X509Sign = (flags & ObjectAttributesFlags.X509Sign) == ObjectAttributesFlags.X509Sign;
        }

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
        public bool FixedTpm { get; }

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
        public bool StClear { get; }

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
        public bool FixedParent { get; }

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
        public bool SensitiveDataOrigin { get; }

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
        public bool UserWithAuth { get; }

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
        public bool AdminWithPolicy { get; }

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
        public bool NoDa { get; }

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
        public bool EncryptedDuplication { get; }

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
        public bool Restricted { get; }

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
        public bool Decrypt { get; }

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
        public bool SignEncrypt { get; }

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
        public bool X509Sign { get; }
    }

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
