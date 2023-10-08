using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions.AndroidKey;

public interface IAndroidKeyAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
        TContext context,
        AndroidKeyAttestationStatement attStmt,
        AuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken);
}
