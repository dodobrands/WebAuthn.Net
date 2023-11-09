using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;

public class DefaultAttestationTrustPathValidator : IAttestationTrustPathValidator
{
    public DefaultAttestationTrustPathValidator(IOptionsMonitor<WebAuthnOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    public virtual bool IsValid(AttestationStatementVerificationResult verificationResult)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (verificationResult is null)
        {
            return false;
        }

        switch (verificationResult.AttestationType)
        {
            case AttestationType.Self:
                {
                    if (verificationResult.AttestationTrustPath is null)
                    {
                        return true;
                    }

                    if (verificationResult.AcceptableTrustAnchors is null)
                    {
                        return false;
                    }

                    return IsValid(
                        verificationResult.AttestationTrustPath,
                        verificationResult.AcceptableTrustAnchors.AttestationRootCertificates.ToArray(),
                        Options.CurrentValue.X509ChainValidation.OnValidateCertificateChain);
                }
            case AttestationType.Basic:
            case AttestationType.AttCa:
            case AttestationType.AnonCa:
                {
                    if (verificationResult.AttestationTrustPath is null)
                    {
                        return false;
                    }

                    if (verificationResult.AcceptableTrustAnchors is null)
                    {
                        return false;
                    }

                    return IsValid(
                        verificationResult.AttestationTrustPath,
                        verificationResult.AcceptableTrustAnchors.AttestationRootCertificates.ToArray(),
                        Options.CurrentValue.X509ChainValidation.OnValidateCertificateChain);
                }
            case AttestationType.None:
                {
                    return true;
                }
            default:
                {
                    return false;
                }
        }
    }

    protected virtual bool IsValid(
        byte[][] attestationTrustPath,
        byte[][] attestationRootCertificates,
        Action<X509Chain> configureChain)
    {
        var isChainOverCertificatesValid = X509TrustChainValidator.IsValidAttestationTrustPath(
            attestationRootCertificates,
            attestationTrustPath,
            configureChain);
        // TODO: validate against rsa key if exists
        var isValid = isChainOverCertificatesValid;
        return isValid;
    }
}
