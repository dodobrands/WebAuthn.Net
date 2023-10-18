using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Apple.Constants;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public static class AppleRoots
{
    public static readonly byte[][] Apple = GetRoots();

    private static byte[][] GetRoots()
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var tpmRootsNamespace = typeof(DefaultAppleAnonymousAttestationStatementVerifier<>).Namespace ?? "";
        var result = new List<byte[]>();
        var embeddedResources = typeof(AppleRoots).Assembly.GetManifestResourceNames();
        foreach (var embeddedResource in embeddedResources.Where(x =>
                     x.EndsWith(".der", StringComparison.Ordinal)
                     && x.Contains(tpmRootsNamespace, StringComparison.Ordinal)))
        {
            var parts = embeddedResource.Split('.').SkipWhile(static x => x != rootCertificatesDirectory).ToList();
            if (parts.Count > 0 && parts.First() == rootCertificatesDirectory)
            {
                parts.RemoveAt(0);
            }

            if (parts.Count < 1)
            {
                throw new InvalidOperationException($"Can't get TPM vendor name from resource name: {embeddedResource}");
            }

            using var resourceStream = typeof(AppleRoots).Assembly.GetManifestResourceStream(embeddedResource);
            if (resourceStream is null)
            {
                throw new InvalidOperationException($"Can't read embedded resource: {embeddedResource}");
            }

            using var memoryStream = new MemoryStream();
            resourceStream.CopyTo(memoryStream);
            memoryStream.Seek(0L, SeekOrigin.Begin);
            var certBytes = memoryStream.ToArray();
            using var cert = X509CertificateInMemoryLoader.Load(certBytes);
            result.Add(certBytes);
        }

        if (result.Count < 1)
        {
            throw new InvalidOperationException("There is no embedded certificates for Apple");
        }

        return result.ToArray();
    }
}
