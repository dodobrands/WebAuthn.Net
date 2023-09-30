using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

namespace WebAuthn.Net.Services.RegistrationCeremony.Verification;

public interface IAndroidSafetyNetAttestationStatementVerifier
{
    Result<AttestationStatementVerificationResult> Verify(
        AndroidSafetyNetAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash);
}
