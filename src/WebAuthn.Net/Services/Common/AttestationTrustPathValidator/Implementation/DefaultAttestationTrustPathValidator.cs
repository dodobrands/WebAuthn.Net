using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
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
    /// <remarks>
    ///     <para>
    ///         The <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">attestation trust path</a> of <a href="https://www.w3.org/TR/webauthn-3/#self-attestation">self attestation</a> and of
    ///         <a href="https://www.w3.org/TR/webauthn-3/#none">no attestation</a> is empty, and step 24 of <a href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">§7.1</a> assesses them
    ///         by the policy of the Relying Party only, so a result of these types is valid only if it has no trust path.
    ///     </para>
    ///     <para>
    ///         For the other attestation types, the trust path must chain up to one of the root certificates of the result, or its single certificate must be the single root certificate.
    ///     </para>
    /// </remarks>
    public virtual bool IsValid(VerifiedAttestationStatement verificationResult)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (verificationResult is null)
        {
            return false;
        }

        switch (verificationResult.AttestationType)
        {
            case AttestationType.None:
            case AttestationType.Self:
                {
                    // §6.5.2: "This attestation trust path is either empty (in case of self attestation), or a set of X.509 certificates";
                    // the verification procedures of the packed self attestation (§8.2) and of the none attestation statement format (§8.7) return an empty trust path.
                    // There is nothing to chain up to a root certificate, so a result of these types that has a trust path contradicts the specification and is rejected.
                    return verificationResult.AttestationTrustPath is null;
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
            default:
                {
                    return false;
                }
        }
    }

    /// <summary>
    ///     Validates the <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">attestation trust path</a>
    /// </summary>
    /// <param name="attestationTrustPath"><a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">Attestation trust path</a>, containing a certificate chain that needs to be validated.</param>
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
