using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.RegistrationCeremony.Verification;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.None;

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
