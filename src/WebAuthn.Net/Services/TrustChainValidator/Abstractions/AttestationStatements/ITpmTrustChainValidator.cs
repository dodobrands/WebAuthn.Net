using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.TrustChainValidator.Models;

namespace WebAuthn.Net.Services.TrustChainValidator.Abstractions.AttestationStatements;

public interface ITpmTrustChainValidator<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<TrustChainVerificationResult> VerifyAsync(
        TContext context,
        AttestationType attestationType,
        X509Certificate2[] trustPath,
        CancellationToken cancellationToken);
}
