using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Apple;

public interface IAppleAnonymousAttestationStatementVerifier
{
    Result<AttestationStatementVerificationResult> Verify(
        AppleAnonymousAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash);
}
