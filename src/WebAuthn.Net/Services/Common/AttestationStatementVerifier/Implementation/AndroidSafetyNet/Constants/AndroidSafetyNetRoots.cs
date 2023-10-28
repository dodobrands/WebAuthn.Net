﻿using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet.Constants;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public static class AndroidSafetyNetRoots
{
    public static readonly byte[][] Certificates = GetRootCertificates();

    private static byte[][] GetRootCertificates()
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var rootCertificatesNamespace = typeof(DefaultAndroidSafetyNetAttestationStatementVerifier<>).Namespace ?? "";
        var result = new List<byte[]>();
        var embeddedResources = typeof(AndroidSafetyNetRoots).Assembly.GetManifestResourceNames();
        foreach (var embeddedResource in embeddedResources.Where(x =>
                     x.EndsWith(".der", StringComparison.Ordinal)
                     && x.Contains(rootCertificatesNamespace, StringComparison.Ordinal)))
        {
            var parts = embeddedResource.Split('.').SkipWhile(static x => x != rootCertificatesDirectory).ToList();
            if (parts.Count > 0 && parts.First() == rootCertificatesDirectory)
            {
                parts.RemoveAt(0);
            }

            if (parts.Count < 1)
            {
                throw new InvalidOperationException($"Can't get root certificate from resource name: {embeddedResource}");
            }

            using var resourceStream = typeof(AndroidSafetyNetRoots).Assembly.GetManifestResourceStream(embeddedResource);
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

        if (result.Count < 1)
        {
            throw new InvalidOperationException("There is no embedded root certificates for AndroidSafetyNet");
        }

        return result.ToArray();
    }
}