using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions.None;

public interface INoneAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
        TContext context,
        NoneAttestationStatement attStmt,
        AuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken);
}
