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

/// <summary>
///     Default implementation of <see cref="IAttestationTrustPathValidator" />.
/// </summary>
public class DefaultAttestationTrustPathValidator : IAttestationTrustPathValidator
{
    /// <summary>
    ///     Constructs <see cref="DefaultAttestationTrustPathValidator" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAttestationTrustPathValidator(IOptionsMonitor<WebAuthnOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        Options = options;
    }

    /// <summary>
    ///     Accessor for getting the current value of global options.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <inheritdoc />
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
                        verificationResult.AttestationRootCertificates.ToArray());
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

    /// <summary>
    ///     Verifies that the certificate is self-signed.
    /// </summary>
    /// <param name="certificateBytes">x509v3 certificate.</param>
    /// <returns><see langword="true" /> if the certificate is self-signed, otherwise - <see langword="false" />.</returns>
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

    /// <summary>
    ///     Validates the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-trust-path">attestation trust path</a>
    /// </summary>
    /// <param name="attestationTrustPath"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-trust-path">Attestation trust path</a>, containing a certificate chain that needs to be validated.</param>
    /// <param name="attestationRootCertificates">Root CA certificates, one of which should fit for the verification of the certificate chain specified in the <paramref name="attestationTrustPath" /></param>
    /// <returns><see langword="true" /> if the certificate chain from <paramref name="attestationTrustPath" /> is successfully validated by one of the Root CA certificates specified in <paramref name="attestationRootCertificates" />, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionalAccessQualifierIsNonNullableAccordingToAPIContract")]
    protected virtual bool IsValid(
        byte[][] attestationTrustPath,
        byte[][] attestationRootCertificates)
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
            Options.CurrentValue.X509ChainValidation.OnValidateAttestationTrustPathChain);
        var isValid = isChainOverCertificatesValid;
        return isValid;
    }
}
