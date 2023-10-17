using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Constants;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public static class TpmRoots
{
    public static readonly X509Certificate2[] AMD = GetRoots("AMD");
    public static readonly X509Certificate2[] Atmel = GetRoots("Atmel");
    public static readonly X509Certificate2[] Infineon = GetRoots("Infineon");
    public static readonly X509Certificate2[] Intel = GetRoots("Intel");
    public static readonly X509Certificate2[] Microsoft = GetRoots("Microsoft");
    public static readonly X509Certificate2[] Nationz = GetRoots("Nationz");
    public static readonly X509Certificate2[] NuvotonTechnology = GetRoots("NuvotonTechnology");
    public static readonly X509Certificate2[] STMicroelectronics = GetRoots("STMicroelectronics");

    private static X509Certificate2[] GetRoots(string vendor)
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var tpmRootsNamespace = typeof(DefaultTpmManufacturerVerifier).Namespace ?? "";
        var result = new List<X509Certificate2>();
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
                var cert = new X509Certificate2(certBytes);
                result.Add(cert);
            }
        }

        if (result.Count < 1)
        {
            throw new InvalidOperationException($"There is no embedded certificates for vendor: {vendor}");
        }

        return result.ToArray();
    }
}
