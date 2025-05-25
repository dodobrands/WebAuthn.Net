using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using WebAuthn.Net.Configuration.Options;

namespace WebAuthn.Net.DSL.Fakes;

public static class FakeWebAuthnOptionsFactory
{
    public static WebAuthnOptions Create(ConfigurationManager configurationManager)
    {
        var webAuthnOptions = configurationManager.Get<WebAuthnOptions>() ?? new WebAuthnOptions();
        webAuthnOptions.X509ChainValidation.OnValidateFidoMetadataBlobJwtChain = static chain =>
        {
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.VerificationFlags =
                X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown
                | X509VerificationFlags.IgnoreNotTimeValid;
        };
        webAuthnOptions.X509ChainValidation.OnValidateAttestationTrustPathChain = static chain =>
        {
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.VerificationFlags =
                X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreEndRevocationUnknown
                | X509VerificationFlags.IgnoreNotTimeValid;
        };
        return webAuthnOptions;
    }
}
