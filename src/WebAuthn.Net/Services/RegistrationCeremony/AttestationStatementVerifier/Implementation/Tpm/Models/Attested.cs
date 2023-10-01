namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models;

/// <summary>
///     10.12.11 TPMU_ATTEST
/// </summary>
public class Attested
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
