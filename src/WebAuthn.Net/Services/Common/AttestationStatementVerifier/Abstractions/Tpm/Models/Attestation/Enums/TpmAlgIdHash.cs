using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

/// <summary>
///     <para>
///         9.31 TPMI_ALG_HASH, based on TPM_ALG_ID (UINT16) - TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512, TPM_ALG_SHA256_192, TPM_ALG_SM3_256,
///         TPM_ALG_SHA3_256, TPM_ALG_SHA3_384, TPM_ALG_SHA3_512, TPM_ALG_SHAKE256_192, TPM_ALG_SHAKE256_256, TPM_ALG_SHAKE256_512, +TPM_ALG_NULL
///     </para>
///     <para>
///         The members are the wire-format vocabulary of TPMI_ALG_HASH (Table 77): every hash algorithm that has an algorithm ID assigned by the TCG.
///         Membership does not mean that this library can compute the digest; that is decided separately by the code that hashes.
///     </para>
///     <para>
///         TPM_ALG_NULL is deliberately not a member. The fields decoded with this type are unmarshaled by the reference implementation with TPMI_ALG_HASH_Unmarshal(),
///         which rejects unknown identifiers (TPM_RC_HASH) and rejects TPM_ALG_NULL unless the "+" flag is set:
///         hashAlg of TPMS_SCHEME_HASH and TPMS_SCHEME_ECDAA always without the flag, nameAlg of TPMT_PUBLIC without it except in TPM2_LoadExternal().
///         A WebAuthn credential key can be certified by TPM2_Certify() only if it was created or loaded with its sensitive area, and PublicAttributesValidation() rejects a TPM_ALG_NULL nameAlg for such an object.
///     </para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public enum TpmAlgIdHash : ushort
{
    // 9.31 TPMI_ALG_HASH
    // TPMI_ALG_HASH is an interface type of all the hash algorithms implemented on a specific TPM.
    // The selector in Table 77 indicates all of the hash algorithms that have an algorithm ID assigned by the TCG and does not indicate the algorithms that will be accepted by a TPM.
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
    //
    // Numeric values: 6.3 TPM_ALG_ID (Table 8) and the TCG Algorithm Registry (Table 8 does not list TPM_ALG_SHA256_192 and TPM_ALG_SHAKE256_*);
    // they match TpmTypes.h of the reference implementation.
    // Digest sizes: 10.2.1 TPMU_HA (Table 88).

    /// <summary>
    ///     The SHA1 algorithm (TPM_ALG_SHA1), 20-byte digest.
    /// </summary>
    /// <remarks>
    ///     <para>ISO/IEC 10118-3</para>
    ///     <para>Deprecated in version 184 (see Part 0 v185, 3.1.1.2), still produced by deployed TPMs.</para>
    /// </remarks>
    Sha1 = 0x0004,

    /// <summary>
    ///     The SHA 256 algorithm (TPM_ALG_SHA256), 32-byte digest.
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    Sha256 = 0x000B,

    /// <summary>
    ///     The SHA 384 algorithm (TPM_ALG_SHA384), 48-byte digest.
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    Sha384 = 0x000C,

    /// <summary>
    ///     The SHA 512 algorithm (TPM_ALG_SHA512), 64-byte digest.
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    Sha512 = 0x000D,

    /// <summary>
    ///     SHA 256 truncated to 192 bits (TPM_ALG_SHA256_192), 24-byte digest.
    /// </summary>
    /// <remarks>
    ///     <para>TCG Algorithm Registry</para>
    ///     <para>Listed in Table 77 (TPMI_ALG_HASH) and Table 88 (TPMU_HA); the value 0x000E is taken from the TCG Algorithm Registry and TpmTypes.h of the reference implementation.</para>
    /// </remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Sha256_192 = 0x000E,

    /// <summary>
    ///     SM3 hash algorithm (TPM_ALG_SM3_256), 32-byte digest.
    /// </summary>
    /// <remarks>ISO/IEC 10118-3:2018</remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Sm3_256 = 0x0012,

    /// <summary>
    ///     Hash algorithm producing a 256 bit digest (TPM_ALG_SHA3_256), 32-byte digest.
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Sha3_256 = 0x0027,

    /// <summary>
    ///     Hash algorithm producing a 384 bit digest (TPM_ALG_SHA3_384), 48-byte digest.
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Sha3_384 = 0x0028,

    /// <summary>
    ///     Hash algorithm producing a 512 bit digest (TPM_ALG_SHA3_512), 64-byte digest.
    /// </summary>
    /// <remarks>ISO/IEC 10118-3</remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Sha3_512 = 0x0029,

    /// <summary>
    ///     SHAKE256 with a fixed 192-bit output (TPM_ALG_SHAKE256_192), 24-byte digest.
    /// </summary>
    /// <remarks>
    ///     <para>TCG Algorithm Registry</para>
    ///     <para>Listed in Table 77 (TPMI_ALG_HASH) and Table 88 (TPMU_HA); the value 0x002C is taken from the TCG Algorithm Registry and TpmTypes.h of the reference implementation.</para>
    /// </remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Shake256_192 = 0x002C,

    /// <summary>
    ///     SHAKE256 with a fixed 256-bit output (TPM_ALG_SHAKE256_256), 32-byte digest.
    /// </summary>
    /// <remarks>
    ///     <para>TCG Algorithm Registry</para>
    ///     <para>Listed in Table 77 (TPMI_ALG_HASH) and Table 88 (TPMU_HA); the value 0x002D is taken from the TCG Algorithm Registry and TpmTypes.h of the reference implementation.</para>
    /// </remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Shake256_256 = 0x002D,

    /// <summary>
    ///     SHAKE256 with a fixed 512-bit output (TPM_ALG_SHAKE256_512), 64-byte digest.
    /// </summary>
    /// <remarks>
    ///     <para>TCG Algorithm Registry</para>
    ///     <para>Listed in Table 77 (TPMI_ALG_HASH) and Table 88 (TPMU_HA); the value 0x002E is taken from the TCG Algorithm Registry and TpmTypes.h of the reference implementation.</para>
    /// </remarks>
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    Shake256_512 = 0x002E
}
