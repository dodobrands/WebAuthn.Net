using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions;

public interface IAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<AttestationStatementVerificationResult>> VerifyAttestationStatementAsync(
        TContext context,
        AttestationStatementVerificationRequest request,
        CancellationToken cancellationToken);
}
