using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey.Constants;

/// <summary>
///     Embedded root certificates for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation">Android Key attestation statement</a>.
/// </summary>
public static class AndroidKeyRoots
{
    /// <summary>
    ///     Root CA certificates for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation">Android Key attestation statement</a>.
    /// </summary>
    public static readonly byte[][] Certificates = GetRootCertificates();

    /// <summary>
    ///     Root CA RSA keys for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-key-attestation">Android Key attestation statement</a>.
    /// </summary>
    public static readonly byte[][] RootRsaKeys = GetRootRsaKeys();

    private static byte[][] GetRootCertificates()
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var rootCertificatesNamespace = typeof(DefaultAndroidKeyAttestationStatementVerifier<>).Namespace ?? "";
        var result = new UniqueByteArraysCollection();
        var embeddedResources = typeof(AndroidKeyRoots).Assembly.GetManifestResourceNames();
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

            using var resourceStream = typeof(AndroidKeyRoots).Assembly.GetManifestResourceStream(embeddedResource);
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
            throw new InvalidOperationException("There is no embedded root certificates for Android Key");
        }

        return result.ToArray();
    }

    private static byte[][] GetRootRsaKeys()
    {
        const string rootKeysDirectory = "RootKeys";
        const string rsaKeysDirectory = "RSA";

        var rootRsaKeysNamespace = typeof(DefaultAndroidKeyAttestationStatementVerifier<>).Namespace ?? "";
        var result = new UniqueByteArraysCollection();
        var embeddedResources = typeof(AndroidKeyRoots).Assembly.GetManifestResourceNames();
        foreach (var embeddedResource in embeddedResources.Where(x =>
                     x.EndsWith(".pem", StringComparison.Ordinal)
                     && x.Contains(rootRsaKeysNamespace, StringComparison.Ordinal)))
        {
            var parts = embeddedResource.Split('.').SkipWhile(static x => x != rootKeysDirectory).ToList();
            if (parts.Count > 0 && parts.First() == rootKeysDirectory)
            {
                parts.RemoveAt(0);
            }

            if (parts.Count == 0)
            {
                throw new InvalidOperationException($"Can't get root key from resource name: {embeddedResource}");
            }

            if (parts.First() == rsaKeysDirectory)
            {
                parts.RemoveAt(0);
            }

            if (parts.Count == 0)
            {
                throw new InvalidOperationException($"Can't get root RSA key from resource name: {embeddedResource}");
            }

            using var resourceStream = typeof(AndroidKeyRoots).Assembly.GetManifestResourceStream(embeddedResource);
            if (resourceStream is null)
            {
                throw new InvalidOperationException($"Can't read embedded resource: {embeddedResource}");
            }

            byte[] rsaKeyBytes;
            using (var memoryStream = new MemoryStream())
            {
                resourceStream.CopyTo(memoryStream);
                memoryStream.Seek(0L, SeekOrigin.Begin);
                rsaKeyBytes = memoryStream.ToArray();
            }

            var rsaKeyPem = Encoding.UTF8.GetString(rsaKeyBytes).Trim();

            using (var rsa = RSA.Create())
            {
                rsa.ImportFromPem(rsaKeyPem);
                rsa.ExportParameters(false);
            }

            result.Add(rsaKeyBytes);
        }

        if (result.Count == 0)
        {
            throw new InvalidOperationException("There is no embedded root RSA keys for Android Key");
        }

        return result.ToArray();
    }
}
