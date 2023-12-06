using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Apple.Constants;

/// <summary>
///     Embedded root certificates for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-apple-anonymous-attestation">Apple Anonymous attestation statement</a>.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public static class AppleRoots
{
    /// <summary>
    ///     Root CA certificates for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-apple-anonymous-attestation">Apple Anonymous attestation statement</a>.
    /// </summary>
    public static readonly byte[][] Certificates = GetRootCertificates();

    private static byte[][] GetRootCertificates()
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var rootCertificatesNamespace = typeof(DefaultAppleAnonymousAttestationStatementVerifier<>).Namespace ?? "";
        var result = new UniqueByteArraysCollection();
        var embeddedResources = typeof(AppleRoots).Assembly.GetManifestResourceNames();
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

            using var resourceStream = typeof(AppleRoots).Assembly.GetManifestResourceStream(embeddedResource);
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
            throw new InvalidOperationException("There is no embedded root certificates for Apple");
        }

        return result.ToArray();
    }
}
