using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.AttestationStatementVerifier;

namespace WebAuthn.Net.Services.RegistrationCeremony;

public interface IAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<bool> VerifyAttestationStatementAsync(
        TContext context,
        AttestationStatementVerificationRequest request,
        CancellationToken cancellationToken);
}
