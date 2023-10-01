using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.AndroidSafetyNet;

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
