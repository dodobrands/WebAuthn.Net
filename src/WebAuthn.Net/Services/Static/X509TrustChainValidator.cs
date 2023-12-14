using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     A static utility for validating a chain of x509v3 certificates.
/// </summary>
public static class X509TrustChainValidator
{
    /// <summary>
    ///     Validates a certificate chain that signed the blob obtained from the FIDO Metadata Service.
    /// </summary>
    /// <param name="rootCertificates">Root CA certificates for the rest of the certificate chain.</param>
    /// <param name="trustPath">The chain of intermediate certificates.</param>
    /// <param name="configureChain">A delegate for configuring the behavior of certificate chain validation.</param>
    /// <returns><see langword="true" /> if the certificate chain is valid, otherwise - <see langword="false" />.</returns>
    public static bool IsFidoMetadataBlobJwtChainValid(
        X509Certificate2[] rootCertificates,
        X509Certificate2[] trustPath,
        Action<X509Chain>? configureChain)
    {
        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(rootCertificates?.Length > 0))
        {
            return false;
        }


        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(trustPath?.Length > 0))
        {
            return false;
        }

        using var chain = new X509Chain();
        if (configureChain is not null)
        {
            configureChain(chain);
        }

        var certificateToValidate = trustPath[0];
        var additionalCertificates = trustPath.Skip(1);
        foreach (var additionalCertificate in additionalCertificates)
        {
            chain.ChainPolicy.ExtraStore.Add(additionalCertificate);
        }

        foreach (var rootCertificate in rootCertificates)
        {
            chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
        }

        return chain.Build(certificateToValidate);
    }

    /// <summary>
    ///     Validates the certificate chain of the attestation trust path received during the WebAuthn ceremony.
    /// </summary>
    /// <param name="rootCertificates">Root CA certificates.</param>
    /// <param name="trustPath">Intermediate certificates of the attestation trust path.</param>
    /// <param name="configureChain">A delegate for configuring the behavior of certificate chain validation.</param>
    /// <returns><see langword="true" /> if the certificate chain is valid, otherwise - <see langword="false" />.</returns>
    public static bool IsAttestationTrustPathChainValid(
        byte[][] rootCertificates,
        byte[][] trustPath,
        Action<X509Chain>? configureChain)
    {
        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(rootCertificates?.Length > 0))
        {
            return false;
        }


        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(trustPath?.Length > 0))
        {
            return false;
        }

        var chain = new X509Chain();
        var certificatesToDispose = new List<X509Certificate2>();
        try
        {
            if (configureChain is not null)
            {
                configureChain(chain);
            }

            foreach (var rootCertificateBytes in rootCertificates)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(rootCertificateBytes, out var rootCertificate))
                {
                    rootCertificate?.Dispose();
                    return false;
                }

                certificatesToDispose.Add(rootCertificate);
                chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
            }

            var certificateToValidateBytes = trustPath[0];
            if (!X509CertificateInMemoryLoader.TryLoad(certificateToValidateBytes, out var certificateToValidate))
            {
                certificateToValidate?.Dispose();
                return false;
            }

            certificatesToDispose.Add(certificateToValidate);
            var additionalCertificates = trustPath.Skip(1);
            foreach (var additionalCertificateBytes in additionalCertificates)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(additionalCertificateBytes, out var additionalCertificate))
                {
                    additionalCertificate?.Dispose();
                    return false;
                }

                chain.ChainPolicy.ExtraStore.Add(additionalCertificate);
            }

            return chain.Build(certificateToValidate);
        }
        finally
        {
            chain.Dispose();
            foreach (var certificateToDispose in certificatesToDispose)
            {
                certificateToDispose.Dispose();
            }
        }
    }
}
