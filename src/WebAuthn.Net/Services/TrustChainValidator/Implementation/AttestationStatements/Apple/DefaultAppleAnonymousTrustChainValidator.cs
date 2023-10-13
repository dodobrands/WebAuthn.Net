using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.TrustChainValidator.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.TrustChainValidator.Models;

namespace WebAuthn.Net.Services.TrustChainValidator.Implementation.AttestationStatements.Apple;

public class DefaultAppleAnonymousTrustChainValidator<TContext>
    : IAppleAnonymousTrustChainValidator<TContext> where TContext : class, IWebAuthnContext
{
    // https://www.apple.com/certificateauthority/private/
    // Apple WebAuthn Root CA

    public Task<TrustChainVerificationResult> VerifyAsync(
        TContext context,
        AttestationType attestationType,
        X509Certificate2[] trustPath,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();


        throw new NotImplementedException();
    }
}
