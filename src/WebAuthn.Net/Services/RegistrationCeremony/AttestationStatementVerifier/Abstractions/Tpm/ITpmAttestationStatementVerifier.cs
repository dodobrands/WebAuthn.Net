using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmAttestationStatementVerifier
{
    Result<AttestationStatementVerificationResult> Verify(
        TpmAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash);
}
