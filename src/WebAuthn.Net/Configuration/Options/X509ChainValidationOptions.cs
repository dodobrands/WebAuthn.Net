using System;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Configuration.Options;

public class X509ChainValidationOptions
{
    public Action<X509Chain> OnValidateCertificateChain { get; set; } = chain =>
    {
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
    };
}
