using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation.Constants;

/// <summary>
///     Embedded root certificates of the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate">key attestation of Google</a>,
///     used to recognize the attestation certificate chains that the <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">certificate revocation status list</a>
///     of the Android attestation keys covers. They are not trust anchors: the trust anchors of an attestation statement come from the FIDO Metadata Service.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public static class GoogleAttestationRoots
{
    /// <summary>
    ///     The root certificates that Google publishes for the key attestation: the current ones and the previously issued ones.
    ///     All of them except "Key Attestation CA1" have the same key, the Google Hardware Attestation Root key.
    /// </summary>
    public static readonly byte[][] Certificates = GetRootCertificates();

    private static byte[][] GetRootCertificates()
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var rootCertificatesNamespace = typeof(DefaultAttestationTrustPathValidator).Namespace ?? "";
        var result = new UniqueByteArraysCollection();
        var embeddedResources = typeof(GoogleAttestationRoots).Assembly.GetManifestResourceNames();
        foreach (var embeddedResource in embeddedResources.Where(x =>
                     x.EndsWith(".der", StringComparison.Ordinal)
                     && x.Contains(rootCertificatesNamespace, StringComparison.Ordinal)))
        {
            var parts = embeddedResource.Split('.').SkipWhile(static x => x != rootCertificatesDirectory).ToList();
            if (parts.Count > 0 && parts.First() == rootCertificatesDirectory)
            {
                parts.RemoveAt(0);
            }

            if (parts.Count == 0)
            {
                throw new InvalidOperationException($"Can't get root certificate from resource name: {embeddedResource}");
            }

            using var resourceStream = typeof(GoogleAttestationRoots).Assembly.GetManifestResourceStream(embeddedResource);
            if (resourceStream is null)
            {
                throw new InvalidOperationException($"Can't read embedded resource: {embeddedResource}");
            }

            byte[] certBytes;
            using (var memoryStream = new MemoryStream())
            {
                resourceStream.CopyTo(memoryStream);
                memoryStream.Seek(0L, SeekOrigin.Begin);
                certBytes = memoryStream.ToArray();
            }

            if (!X509CertificateInMemoryLoader.TryLoad(certBytes, out var certificate))
            {
                certificate?.Dispose();
                throw new InvalidOperationException("Invalid certificate");
            }

            certificate.Dispose();
            result.Add(certBytes);
        }

        if (result.Count == 0)
        {
            throw new InvalidOperationException("There is no embedded root certificates for the key attestation of Google");
        }

        return result.ToArray();
    }
}
