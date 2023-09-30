using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

namespace WebAuthn.Net.Services.RegistrationCeremony.Verification;

public interface IAppleAnonymousAttestationStatementVerifier
{
    Result<AttestationStatementVerificationResult> Verify(
        AppleAnonymousAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash);
}
