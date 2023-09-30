using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.RegistrationCeremony.Verification;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.AndroidSafetyNet;

public class DefaultAndroidSafetyNetAttestationStatementVerifier : IAndroidSafetyNetAttestationStatementVerifier
{
    public Result<AttestationStatementVerificationResult> Verify(
        AndroidSafetyNetAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        throw new NotImplementedException();
    }
}
