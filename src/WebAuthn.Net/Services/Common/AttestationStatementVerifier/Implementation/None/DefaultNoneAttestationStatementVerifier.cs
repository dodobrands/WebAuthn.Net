using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.None;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.None;

public class DefaultNoneAttestationStatementVerifier<TContext> :
    INoneAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    public Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
        TContext context,
        NoneAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-none-attestation
        // §8.7. None Attestation Statement Format
        var result = new AttestationStatementVerificationResult(
            AttestationStatementFormat.None,
            AttestationType.None,
            null,
            null);
        return Task.FromResult(Result<AttestationStatementVerificationResult>.Success(result));
    }
}
