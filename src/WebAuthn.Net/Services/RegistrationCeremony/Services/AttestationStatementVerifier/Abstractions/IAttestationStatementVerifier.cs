using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions;

public interface IAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<AttestationStatementVerificationResult>> VerifyAttestationStatementAsync(
        TContext context,
        AttestationStatementFormat fmt,
        AbstractAttestationStatement attStmt,
        AuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken);
}
