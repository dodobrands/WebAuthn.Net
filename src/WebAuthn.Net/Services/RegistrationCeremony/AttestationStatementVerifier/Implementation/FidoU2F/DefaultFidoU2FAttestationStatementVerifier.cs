using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.FidoU2F;

public class DefaultFidoU2FAttestationStatementVerifier : IFidoU2FAttestationStatementVerifier
{
    public Result<AttestationStatementVerificationResult> Verify(
        FidoU2FAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        throw new NotImplementedException();
    }
}
