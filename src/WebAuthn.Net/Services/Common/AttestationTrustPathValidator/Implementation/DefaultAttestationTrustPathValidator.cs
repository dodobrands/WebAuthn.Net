using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
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

    public virtual bool IsValid(VerifiedAttestationStatement verificationResult)
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

                    if (verificationResult.AttestationRootCertificates is null)
                    {
                        if (verificationResult.AttestationTrustPath.Length != 1)
                        {
                            return false;
                        }

                        var certificateBytes = verificationResult.AttestationTrustPath.Single();
                        return IsSelfSigned(certificateBytes);
                    }

                    if (verificationResult.AttestationRootCertificates.Count == 1
                        && verificationResult.AttestationTrustPath.Length == 1)
                    {
                        var rootCertificate = verificationResult.AttestationRootCertificates.Single();
                        var trustPath = verificationResult.AttestationTrustPath.Single();
                        return rootCertificate.AsSpan().SequenceEqual(trustPath.AsSpan());
                    }

                    return false;
                }
            case AttestationType.Basic:
            case AttestationType.AttCa:
            case AttestationType.AnonCa:
                {
                    if (verificationResult.AttestationTrustPath is null)
                    {
                        return false;
                    }

                    if (verificationResult.AttestationRootCertificates is null)
                    {
                        return false;
                    }


                    return IsValid(
                        verificationResult.AttestationTrustPath,
                        verificationResult.AttestationRootCertificates.ToArray(),
                        Options.CurrentValue.X509ChainValidation.OnValidateAttestationTrustPathChain);
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

    protected virtual bool IsSelfSigned(byte[] certificateBytes)
    {
        const string authorityKeyIdentifier = "2.5.29.35";
        const string subjectKeyIdentifier = "2.5.29.14";
        X509Certificate2? certificate = null;
        try
        {
            if (!X509CertificateInMemoryLoader.TryLoad(certificateBytes, out certificate))
            {
                return false;
            }

            var subjectAndIssuerSame = certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData);

            var authorityKeyIdentifierExt = certificate.Extensions.FirstOrDefault(x => x.Oid?.Value == authorityKeyIdentifier);
            var subjectKeyIdentifierExt = certificate.Extensions.FirstOrDefault(x => x.Oid?.Value == subjectKeyIdentifier);

            if (authorityKeyIdentifierExt is not null && subjectKeyIdentifierExt is not null)
            {
                var idsAreSame = authorityKeyIdentifierExt.RawData.AsSpan().SequenceEqual(subjectKeyIdentifierExt.RawData.AsSpan());
                return idsAreSame && subjectAndIssuerSame;
            }
            else
            {
                return subjectAndIssuerSame;
            }
        }
        finally
        {
            certificate?.Dispose();
        }
    }

    [SuppressMessage("ReSharper", "ConditionalAccessQualifierIsNonNullableAccordingToAPIContract")]
    protected virtual bool IsValid(
        byte[][] attestationTrustPath,
        byte[][] attestationRootCertificates,
        Action<X509Chain> configureChain)
    {
        if (!(attestationTrustPath?.Length > 0 && attestationRootCertificates?.Length > 0))
        {
            return false;
        }

        if (attestationRootCertificates.Length == 1 && attestationTrustPath.Length == 1)
        {
            var rootCertificate = attestationRootCertificates.Single();
            var trustPath = attestationTrustPath.Single();
            if (rootCertificate.AsSpan().SequenceEqual(trustPath.AsSpan()))
            {
                return true;
            }
        }

        var isChainOverCertificatesValid = X509TrustChainValidator.IsAttestationTrustPathChainValid(
            attestationRootCertificates,
            attestationTrustPath,
            configureChain);
        var isValid = isChainOverCertificatesValid;
        return isValid;
    }
}
