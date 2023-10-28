namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     10.12.3 TPMS_CERTIFY_INFO
/// </summary>
public class Certify
{
    public Certify(Tpm2BName name, Tpm2BName qualifiedName)
    {
        Name = name;
        QualifiedName = qualifiedName;
    }
    // 10.12.3 TPMS_CERTIFY_INFO
    // This is the attested data for TPM2_Certify().
    // Table 123 — Definition of TPMS_CERTIFY_INFO Structure <OUT>
    // | Parameter     | Type       | Description
    // | name          | TPM2B_NAME | Name of the certified object
    // | qualifiedName | TPM2B_NAME | Qualified Name of the certified object

    public Tpm2BName Name { get; }

    public Tpm2BName QualifiedName { get; }
}
