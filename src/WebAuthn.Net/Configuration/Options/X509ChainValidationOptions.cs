using System;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define the behavior of X509v3 certificate chain validation.
/// </summary>
public class X509ChainValidationOptions
{
    /// <summary>
    ///     A delegate that is called during the validation of the X509v3 certificate chain of a metadata blob returned by the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.
    /// </summary>
    public Action<X509Chain> OnValidateFidoMetadataBlobJwtChain { get; set; } = chain =>
    {
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
    };

    /// <summary>
    ///     A delegate that is called during the validation of the X509v3 certificate chain of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-trust-path">attestation trust path</a>.
    /// </summary>
    public Action<X509Chain> OnValidateAttestationTrustPathChain { get; set; } = chain =>
    {
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
    };
}
