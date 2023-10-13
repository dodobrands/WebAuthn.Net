using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.TrustChainValidator.Models;

namespace WebAuthn.Net.Services.TrustChainValidator.Abstractions;

public interface ITrustChainValidator<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<TrustChainVerificationResult> VerifyAsync(
        TContext context,
        AttestationStatementVerificationResult verificationResult,
        CancellationToken cancellationToken);
}
