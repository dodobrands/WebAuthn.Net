using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.Static;

public static class X509TrustChainValidator
{
    public static bool IsValidCertificateChain(X509Certificate2[] rootCertificates, X509Certificate2[] trustPath)
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
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
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

    public static bool IsValidAttestationTrustPath(
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
