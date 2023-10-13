using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.TrustChainValidator.Abstractions;
using WebAuthn.Net.Services.TrustChainValidator.Models;

namespace WebAuthn.Net.Services.TrustChainValidator.Implementation;

public class DefaultTrustChainValidator<TContext>
    : ITrustChainValidator<TContext> where TContext : class, IWebAuthnContext
{
    public virtual Task<TrustChainVerificationResult> VerifyAsync(
        TContext context,
        AttestationStatementVerificationResult verificationResult,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(verificationResult);
        cancellationToken.ThrowIfCancellationRequested();
        switch (verificationResult.Fmt)
        {
            case AttestationStatementFormat.Packed:
                break;
            case AttestationStatementFormat.Tpm:
                break;
            case AttestationStatementFormat.AndroidKey:
                break;
            case AttestationStatementFormat.AndroidSafetynet:
                break;
            case AttestationStatementFormat.FidoU2F:
                break;
            case AttestationStatementFormat.AppleAnonymous:
                break;
            case AttestationStatementFormat.None:
                break;
            default:
                throw new NotImplementedException();
        }

        throw new NotImplementedException();
    }
}
