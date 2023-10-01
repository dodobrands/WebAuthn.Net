using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Packed;

public interface IPackedAttestationStatementVerifier
{
    Result<AttestationStatementVerificationResult> Verify(
        PackedAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash);
}
