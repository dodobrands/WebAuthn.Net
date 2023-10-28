using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator;

public interface IAttestationTrustPathValidator
{
    bool IsValid(AttestationStatementVerificationResult verificationResult);
}
