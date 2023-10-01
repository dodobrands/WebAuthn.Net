using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.Apple;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Apple;

public class DefaultAppleAnonymousAttestationStatementVerifier : IAppleAnonymousAttestationStatementVerifier
{
    public Result<AttestationStatementVerificationResult> Verify(
        AppleAnonymousAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        throw new NotImplementedException();
    }
}
