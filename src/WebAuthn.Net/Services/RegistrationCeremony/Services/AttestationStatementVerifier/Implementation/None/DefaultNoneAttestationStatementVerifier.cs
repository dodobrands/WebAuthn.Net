using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions.None;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.None;

public class DefaultNoneAttestationStatementVerifier<TContext> :
    INoneAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    public Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
        TContext context,
        NoneAttestationStatement attStmt,
        AuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-none-attestation
        // §8.7. None Attestation Statement Format

        var result = new AttestationStatementVerificationResult(AttestationType.None);
        return Task.FromResult(Result<AttestationStatementVerificationResult>.Success(result));
    }
}
