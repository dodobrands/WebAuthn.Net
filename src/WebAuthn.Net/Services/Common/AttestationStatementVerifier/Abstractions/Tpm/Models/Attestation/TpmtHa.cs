using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.3.2 TPMT_HA</para>
///     <para>The basic hash-agile structure used in the TPM specification.</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class TpmtHa
{
    // 10.3.2 TPMT_HA
    // Table 79 shows the basic hash-agile structure used in this specification.
    // To handle hash agility, this structure uses the hashAlg parameter to indicate the algorithm used to compute the digest and,
    // by implication, the size of the digest.
    // Table 79 — Definition of TPMT_HA Structure <IN/OUT>
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
