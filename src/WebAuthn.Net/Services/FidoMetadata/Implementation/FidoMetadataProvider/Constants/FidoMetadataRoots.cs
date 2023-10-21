using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;

public static class FidoMetadataRoots
{
    public static readonly byte[][] GlobalSign = GetRoots();

    private static byte[][] GetRoots()
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var tpmRootsNamespace = typeof(DefaultFidoMetadataProvider).Namespace ?? "";
        var result = new List<byte[]>();
        var embeddedResources = typeof(FidoMetadataRoots).Assembly.GetManifestResourceNames();
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

            using var resourceStream = typeof(FidoMetadataRoots).Assembly.GetManifestResourceStream(embeddedResource);
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
            throw new InvalidOperationException("There is no embedded certificates for FidoMetadata");
        }

        return result.ToArray();
    }
}
