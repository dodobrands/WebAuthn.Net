namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

/// <summary>
///     10.12.11 TPMU_ATTEST
/// </summary>
public class Attested
{
    public Attested(Certify certify)
    {
        Certify = certify;
    }
    // According to the WebAuthn specification, only TPM_ST_ATTEST_CERTIFY is allowed
    // 10.12.11 TPMU_ATTEST
    // Table 131 — Definition of TPMU_ATTEST Union <OUT>
    // | Parameter | Type              | Selector
    // | certify   | TPMS_CERTIFY_INFO | TPM_ST_ATTEST_CERTIFY

    public Certify Certify { get; }
}
