using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.None;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.None;

public class DefaultNoneAttestationStatementVerifier : INoneAttestationStatementVerifier
{
    public Result<AttestationStatementVerificationResult> Verify(
        NoneAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        var result = new AttestationStatementVerificationResult(AttestationType.None);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }
}
