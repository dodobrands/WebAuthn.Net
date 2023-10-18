using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Constants;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public static class TpmRoots
{
    public static readonly byte[][] AMD = GetRoots("AMD");
    public static readonly byte[][] Atmel = GetRoots("Atmel");
    public static readonly byte[][] Infineon = GetRoots("Infineon");
    public static readonly byte[][] Intel = GetRoots("Intel");
    public static readonly byte[][] Microsoft = GetRoots("Microsoft");
    public static readonly byte[][] Nationz = GetRoots("Nationz");
    public static readonly byte[][] NuvotonTechnology = GetRoots("NuvotonTechnology");
    public static readonly byte[][] STMicroelectronics = GetRoots("STMicroelectronics");

    private static byte[][] GetRoots(string vendor)
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var tpmRootsNamespace = typeof(DefaultTpmManufacturerVerifier).Namespace ?? "";
        var result = new List<byte[]>();
        var embeddedResources = typeof(TpmRoots).Assembly.GetManifestResourceNames();
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

            var actualVendor = parts.First();
            if (actualVendor == vendor)
            {
                using var resourceStream = typeof(TpmRoots).Assembly.GetManifestResourceStream(embeddedResource);
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
        }

        if (result.Count < 1)
        {
            throw new InvalidOperationException($"There is no embedded certificates for vendor: {vendor}");
        }

        return result.ToArray();
    }
}
