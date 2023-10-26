using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.AttestationStatementVerifier;

namespace WebAuthn.Net.Services.AttestationTrustPathValidator;

public interface IAttestationTrustPathValidator
{
    bool IsValid(AttestationStatementVerificationResult verificationResult);
}
