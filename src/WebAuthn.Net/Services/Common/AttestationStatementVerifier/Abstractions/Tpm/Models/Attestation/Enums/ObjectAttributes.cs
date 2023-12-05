using System;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>8.3 TPMA_OBJECT (UINT32) - Object Attributes</para>
///     <para>
///         This attribute structure indicates an object's use, its authorization types, and its relationship to other objects.
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
/// </remarks>
[Flags]
public enum ObjectAttributes : uint
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
