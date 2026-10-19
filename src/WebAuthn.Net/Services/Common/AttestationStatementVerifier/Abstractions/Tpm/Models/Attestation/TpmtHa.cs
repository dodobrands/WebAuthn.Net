using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.2.2 TPMT_HA</para>
///     <para>The basic hash-agile structure used in the TPM specification.</para>
///     <para>When transmitted, only the number of octets indicated by hashAlg is sent, so the length of the digest is fixed by the hash algorithm (Table 88).</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class TpmtHa
{
    // 10.2.2 TPMT_HA
    // Table 89 shows the basic hash-agile structure used in this specification.
    // To handle hash agility, this structure uses the hashAlg parameter to indicate the algorithm used to compute the digest and,
    // by implication, the size of the digest.
    // When transmitted, only the number of octets indicated by hashAlg is sent.
    // Table 89: Definition of TPMT_HA Structure
    // | Parameter        | Type           | Description
    // | hashAlg          | +TPMI_ALG_HASH | selector of the hash contained in the digest that implies the size of the digest
    // | [hashAlg] digest | TPMU_HA        | the digest data

    /// <summary>
    ///     Constructs <see cref="TpmtHa" />.
    /// </summary>
    /// <param name="hashAlg">Selector of the hash contained in the digest that implies the size of the digest.</param>
    /// <param name="digest">The digest data.</param>
    public TpmtHa(TpmAlgIdHash hashAlg, byte[] digest)
    {
        HashAlg = hashAlg;
        Digest = digest;
    }

    /// <summary>
    ///     Selector of the hash contained in the digest that implies the size of the digest.
    /// </summary>
    public TpmAlgIdHash HashAlg { get; }

    /// <summary>
    ///     The digest data.
    /// </summary>
    public byte[] Digest { get; }
}
