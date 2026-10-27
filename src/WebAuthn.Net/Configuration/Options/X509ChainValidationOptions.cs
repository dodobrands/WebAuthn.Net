using System;
using System.Security.Cryptography.X509Certificates;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngest;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define the behavior of X509v3 certificate chain validation.
/// </summary>
public class X509ChainValidationOptions
{
    /// <summary>
    ///     A delegate that is called during the validation of the X509v3 certificate chain of a metadata blob returned by the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.
    /// </summary>
    /// <remarks>
    ///     <see cref="X509ChainPolicy.TrustMode" /> is set to <see cref="X509ChainTrustMode.CustomRootTrust" /> before this delegate is called, so that only the root certificates of the FIDO Metadata Service are trust anchors.
    /// </remarks>
    public Action<X509Chain> OnValidateFidoMetadataBlobJwtChain { get; set; } = chain =>
    {
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    };

    /// <summary>
    ///     A delegate that is called during the validation of the X509v3 certificate chain of the metadata blob embedded in the application
    ///     (see <see cref="FidoMetadataIngestBackgroundServiceOptions.EmbeddedBlob" />).
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The embedded blob is a part of the application: it has been obtained from the FIDO Metadata Service when the application was built, and it is used when the FIDO Metadata Service is unavailable.
    ///         Its signature and its certificate chain up to the root certificates of the FIDO Metadata Service are verified like those of a downloaded blob, but the default delegate doesn't check
    ///         what describes the signing certificates at the current time rather than at the time the blob was signed:
    ///     </para>
    ///     <list type="bullet">
    ///         <item>
    ///             <description>
    ///                 the validity period (<see cref="X509VerificationFlags.IgnoreNotTimeValid" />): the blobs are signed with short-lived certificates (the certificate of the blob published in October 2026 is valid for about 200 days),
    ///                 so a blob embedded in the application would otherwise become unusable within months, or within days if it was signed shortly before its certificate expired;
    ///             </description>
    ///         </item>
    ///         <item>
    ///             <description>
    ///                 the revocation status (<see cref="X509RevocationMode.NoCheck" />, and <see cref="X509ChainPolicy.DisableCertificateDownloads" /> is <see langword="true" />): it can't be checked without the network,
    ///                 and certification authorities may stop publishing the revocation status of a certificate once it expires.
    ///             </description>
    ///         </item>
    ///     </list>
    ///     <para>
    ///         This doesn't affect the blobs downloaded from the FIDO Metadata Service, which are validated according to <see cref="OnValidateFidoMetadataBlobJwtChain" />.
    ///         <see cref="X509ChainPolicy.TrustMode" /> is set to <see cref="X509ChainTrustMode.CustomRootTrust" /> before this delegate is called.
    ///     </para>
    /// </remarks>
    public Action<X509Chain> OnValidateEmbeddedFidoMetadataBlobJwtChain { get; set; } = chain =>
    {
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
    };

    /// <summary>
    ///     A delegate that is called during the validation of the X509v3 certificate chain of the <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">attestation trust path</a>.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The chain being validated is built from the certificates supplied by the client in the attestation statement, i.e. from untrusted input.
    ///         The trust anchors always come from the FIDO Metadata Service or from the roots embedded in the library, and the intermediate certificates always come from the attestation statement itself,
    ///         so the chain engine never needs to touch the network: <see cref="X509ChainPolicy.DisableCertificateDownloads" /> is set to <see langword="true" /> and <see cref="X509ChainPolicy.RevocationMode" /> to
    ///         <see cref="X509RevocationMode.NoCheck" /> before this delegate is called (and by the default delegate), which prevents the chain engine from fetching issuer certificates from the URLs
    ///         embedded in the client-supplied certificates (Authority Information Access) and from fetching their CRLs or OCSP responses. On macOS the chain engine fetches the issuer certificates whenever
    ///         revocation checking is enabled, regardless of <see cref="X509ChainPolicy.DisableCertificateDownloads" />, so both settings are needed.
    ///     </para>
    ///     <para>
    ///         Re-enabling the downloads or the revocation checking in a custom delegate lets a client make the server issue HTTP requests to arbitrary URLs and block for <see cref="X509ChainPolicy.UrlRetrievalTimeout" /> per request.
    ///         The revocation of attestation certificates is not expressed through X.509 revocation lists in practice: the FIDO Metadata Service publishes the status of authenticator models, and the library rejects the attestation of
    ///         compromised or revoked models instead, even if it chains up to a root certificate embedded in the library (see <see cref="FidoMetadataSearchError.Untrusted" />).
    ///     </para>
    ///     <para>
    ///         The default delegate doesn't ignore any chain validation error (<see cref="X509ChainPolicy.VerificationFlags" /> is <see cref="X509VerificationFlags.NoFlag" />).
    ///         Relaxations that only a test environment needs (for example, the FIDO Conformance demo ignores an unknown revocation status) belong in the delegate configured for that environment.
    ///     </para>
    /// </remarks>
    public Action<X509Chain> OnValidateAttestationTrustPathChain { get; set; } = chain =>
    {
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        // The attestation trust path is attacker-controlled: the chain engine must not fetch anything named by the client-supplied certificates.
        // - no CRL / OCSP: X.509 revocation is not how the status of attestation certificates is published (the FIDO Metadata Service is), and the chain engine's revocation checking
        //   would fetch the CRL Distribution Point / OCSP URLs of the client-supplied certificates (Online mode) or, on macOS, enable the network for the whole evaluation (Offline mode too);
        // - no Authority Information Access downloads: the issuer certificates are either in the attestation statement itself or are the trust anchors.
        // Each unreachable URL would otherwise block the request thread for UrlRetrievalTimeout.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    };
}
