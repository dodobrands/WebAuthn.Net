namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.12.3 TPMS_CERTIFY_INFO</para>
///     <para>The attested data for TPM2_Certify().</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM 2.0 Library - Part 2: Structures, Family "2.0", Level 00 Revision 01.59, November 8, 2019</a>
///     </para>
/// </remarks>
public class Certify
{
    // 10.12.3 TPMS_CERTIFY_INFO
    // This is the attested data for TPM2_Certify().
    // Table 123 — Definition of TPMS_CERTIFY_INFO Structure <OUT>
    // | Parameter     | Type       | Description
    // | name          | TPM2B_NAME | Name of the certified object
    // | qualifiedName | TPM2B_NAME | Qualified Name of the certified object

    /// <summary>
    ///     Constructs <see cref="Certify" />.
    /// </summary>
    /// <param name="name">Name of the certified object</param>
    /// <param name="qualifiedName">Qualified Name of the certified object</param>
    public Certify(Tpm2BName name, Tpm2BName qualifiedName)
    {
        Name = name;
        QualifiedName = qualifiedName;
    }

    /// <summary>
    ///     Name of the certified object
    /// </summary>
    public Tpm2BName Name { get; }

    /// <summary>
    ///     Qualified Name of the certified object
    /// </summary>
    public Tpm2BName QualifiedName { get; }
}
