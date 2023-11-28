using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.FidoU2F;

public interface IFidoU2FAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        FidoU2FAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken);
}
