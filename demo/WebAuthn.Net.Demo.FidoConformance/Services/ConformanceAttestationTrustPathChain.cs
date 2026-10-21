using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Demo.FidoConformance.Services;

/// <summary>
///     The <see cref="X509Chain" /> policy for validating the attestation trust path while the FIDO Conformance Tools test the server.
/// </summary>
/// <remarks>
///     <para>
///         The library default ignores no chain validation error. The conformance runs keep the relaxation that the library used to apply by default for them:
///         an unknown revocation status of the certification authority and end certificates is ignored. When the revocation is checked by the chain engine without downloading the CRLs
///         (<see cref="X509RevocationMode.Offline" />), the revocation status of the certificates the FIDO Conformance Tools issue for the attestation statements is unknown.
///     </para>
///     <para>
///         As long as <see cref="X509ChainPolicy.RevocationMode" /> is <see cref="X509RevocationMode.NoCheck" />, as in the library default, the chain engine doesn't report the revocation status at all
///         and the flags have no effect. They take effect when the revocation checking is enabled here, for example, to investigate a conformance test.
///     </para>
/// </remarks>
public static class ConformanceAttestationTrustPathChain
{
    /// <summary>
    ///     Configures the <see cref="X509Chain" /> used for validating the attestation trust path: the same policy as the library default,
    ///     except that an unknown revocation status of the certification authority and end certificates is ignored.
    /// </summary>
    /// <param name="chain">The chain to configure.</param>
    public static void Configure(X509Chain chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags =
            X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
            | X509VerificationFlags.IgnoreEndRevocationUnknown;
    }
}
