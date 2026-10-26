using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
    /// <param name="trustPath">Certificates from the JWS (JWT) token header in the order they appear in the header (the first certificate is the one that signed the token).</param>
    /// <param name="configureChain">A delegate for configuring the behavior of certificate chain validation.</param>
    /// <returns><see langword="true" /> if the certificate chain is valid, otherwise - <see langword="false" />.</returns>
    public static bool IsFidoMetadataBlobJwtChainValid(
        X509Certificate2[] rootCertificates,
        X509Certificate2[] trustPath,
        Action<X509Chain>? configureChain)
    {
        return IsFidoMetadataBlobJwtChainValid(rootCertificates, trustPath, configureChain, out _);
    }

    /// <summary>
    ///     Validates a certificate chain that signed the blob obtained from the FIDO Metadata Service and returns the status of the built chain.
    /// </summary>
    /// <param name="rootCertificates">Root CA certificates for the rest of the certificate chain.</param>
    /// <param name="trustPath">Certificates from the JWS (JWT) token header in the order they appear in the header (the first certificate is the one that signed the token).</param>
    /// <param name="configureChain">A delegate for configuring the behavior of certificate chain validation.</param>
    /// <param name="chainStatus">
    ///     Output parameter. The status of the built chain: an empty array if the chain is valid or could not be built because of the invalid arguments,
    ///     otherwise - the flags describing why the chain is invalid (for example, <see cref="X509ChainStatusFlags.RevocationStatusUnknown" />).
    /// </param>
    /// <returns><see langword="true" /> if the certificate chain is valid, otherwise - <see langword="false" />.</returns>
    public static bool IsFidoMetadataBlobJwtChainValid(
        X509Certificate2[] rootCertificates,
        X509Certificate2[] trustPath,
        Action<X509Chain>? configureChain,
        out X509ChainStatus[] chainStatus)
    {
        X509Chain? chain = null;
        try
        {
            return TryBuildFidoMetadataBlobJwtChain(rootCertificates, trustPath, configureChain, out chain, out chainStatus);
        }
        finally
        {
            chain?.Dispose();
        }
    }

    /// <summary>
    ///     Builds and validates the certificate chain of the JWS (JWT) token of a blob obtained from the FIDO Metadata Service and returns the built chain,
    ///     so that the caller can perform additional validation of its elements (for example, a custom revocation check).
    /// </summary>
    /// <remarks>
    ///     Before <paramref name="configureChain" /> is called, the chain policy is set to <see cref="X509ChainTrustMode.CustomRootTrust" />, so that only <paramref name="rootCertificates" /> are trust anchors
    ///     even if the delegate doesn't set the trust mode itself (<see cref="X509Chain" /> doesn't allow the custom root certificates in the default trust mode).
    /// </remarks>
    /// <param name="rootCertificates">Root CA certificates.</param>
    /// <param name="trustPath">Certificates from the JWS (JWT) token header in the order they appear in the header (the first certificate is the one that signed the token).</param>
    /// <param name="configureChain">A delegate for configuring the behavior of certificate chain validation.</param>
    /// <param name="chain">
    ///     Output parameter. The successfully built chain if the method returns <see langword="true" />, otherwise - <see langword="null" />.
    ///     The caller is responsible for disposing the returned chain.
    /// </param>
    /// <param name="chainStatus">
    ///     Output parameter. The status of the built chain: an empty array if the chain is valid or could not be built because of the invalid arguments,
    ///     otherwise - the flags describing why the chain is invalid (for example, <see cref="X509ChainStatusFlags.RevocationStatusUnknown" />).
    /// </param>
    /// <returns><see langword="true" /> if the certificate chain is valid, otherwise - <see langword="false" />.</returns>
    public static bool TryBuildFidoMetadataBlobJwtChain(
        X509Certificate2[] rootCertificates,
        X509Certificate2[] trustPath,
        Action<X509Chain>? configureChain,
        [NotNullWhen(true)] out X509Chain? chain,
        out X509ChainStatus[] chainStatus)
    {
        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(rootCertificates?.Length > 0))
        {
            chain = null;
            chainStatus = Array.Empty<X509ChainStatus>();
            return false;
        }


        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(trustPath?.Length > 0))
        {
            chain = null;
            chainStatus = Array.Empty<X509ChainStatus>();
            return false;
        }

        var builtChain = new X509Chain();
        try
        {
            // The trust anchors are only the provided root certificates, also for a custom delegate that doesn't set the trust mode
            // (in the default trust mode X509Chain rejects the custom root certificates with an exception).
            builtChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            if (configureChain is not null)
            {
                configureChain(builtChain);
            }

            var certificateToValidate = trustPath[0];
            var additionalCertificates = trustPath.Skip(1);
            foreach (var additionalCertificate in additionalCertificates)
            {
                builtChain.ChainPolicy.ExtraStore.Add(additionalCertificate);
            }

            foreach (var rootCertificate in rootCertificates)
            {
                builtChain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
            }

            if (builtChain.Build(certificateToValidate))
            {
                chain = builtChain;
                chainStatus = Array.Empty<X509ChainStatus>();
                return true;
            }

            chainStatus = builtChain.ChainStatus;
        }
        catch
        {
            builtChain.Dispose();
            throw;
        }

        builtChain.Dispose();
        chain = null;
        return false;
    }

    /// <summary>
    ///     Validates the certificate chain of the attestation trust path received during the WebAuthn ceremony.
    /// </summary>
    /// <remarks>
    ///     The <paramref name="trustPath" /> is supplied by the client, i.e. it is untrusted input. Before <paramref name="configureChain" /> is called, the chain policy is set to
    ///     <see cref="X509ChainTrustMode.CustomRootTrust" /> (only <paramref name="rootCertificates" /> are trust anchors), <see cref="X509ChainPolicy.DisableCertificateDownloads" /> is set to <see langword="true" />
    ///     and <see cref="X509ChainPolicy.RevocationMode" /> to <see cref="X509RevocationMode.NoCheck" />, so that the chain engine never fetches issuer certificates, CRLs or OCSP responses from the URLs
    ///     embedded in the client-supplied certificates; a custom <paramref name="configureChain" /> delegate has to opt in explicitly to change this.
    /// </remarks>
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
            // Safe defaults for an attacker-controlled chain, applied before the delegate so that a custom delegate has to opt in explicitly:
            // - the trust anchors are only the provided root certificates (the system store is not consulted);
            // - the chain engine must not download missing issuer certificates from the Authority Information Access URLs of the client-supplied certificates
            //   (the download is performed synchronously and blocks for UrlRetrievalTimeout per unreachable URL);
            // - the chain engine must not fetch CRLs or OCSP responses either: the .NET default is Online, and on macOS any revocation checking (Offline too) lets the chain engine
            //   use the network for the whole evaluation, including the issuer certificate downloads, regardless of DisableCertificateDownloads.
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
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

                certificatesToDispose.Add(additionalCertificate);
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
