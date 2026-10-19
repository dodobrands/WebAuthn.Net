namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

/// <summary>
///     <para>10.11.3 TPMS_CERTIFY_INFO</para>
///     <para>The attested data for TPM2_Certify().</para>
/// </summary>
/// <remarks>
///     <para>
///         <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library</a>
///     </para>
///     <para>
///         <a href="https://cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf">TPM 2.0 Library - Part 2: Structures, Version 185, March 12, 2026</a>
///     </para>
/// </remarks>
public class Certify
{
    // 10.11.3 TPMS_CERTIFY_INFO
    // This is the attested data for TPM2_Certify().
    // Table 145: Definition of TPMS_CERTIFY_INFO Structure
    // | Parameter     | Type       | Description
    // | name          | TPM2B_NAME | Name of the certified object
    // | qualifiedName | TPM2B_NAME | Qualified Name of the certified object

    /// <summary>
    ///     Constructs <see cref="Certify" />.
    /// </summary>
    /// <param name="name">Name of the certified object</param>
    /// <param name="qualifiedName">Qualified Name of the certified object. An Empty Buffer for an anonymous (ECDAA) signing scheme. Ignored by WebAuthn.</param>
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
    ///     <para>Qualified Name of the certified object.</para>
    ///     <para>An Empty Buffer for an anonymous (ECDAA) signing scheme. Ignored by WebAuthn.</para>
    /// </summary>
    public Tpm2BName QualifiedName { get; }
}
