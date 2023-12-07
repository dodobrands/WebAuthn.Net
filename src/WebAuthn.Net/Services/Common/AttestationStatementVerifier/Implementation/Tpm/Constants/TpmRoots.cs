using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

/// <summary>
///     Embedded root certificates for the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-tpm-attestation">TPM attestation statement</a>.
/// </summary>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public static class TpmRoots
{
    /// <summary>
    ///     Advanced Micro Devices, Inc.
    /// </summary>
    public static readonly byte[][] AMD = GetRoots("AMD");

    /// <summary>
    ///     Atmel
    /// </summary>
    public static readonly byte[][] Atmel = GetRoots("Atmel");

    /// <summary>
    ///     Infineon
    /// </summary>
    public static readonly byte[][] Infineon = GetRoots("Infineon");

    /// <summary>
    ///     Intel
    /// </summary>
    public static readonly byte[][] Intel = GetRoots("Intel");

    /// <summary>
    ///     Microsoft
    /// </summary>
    public static readonly byte[][] Microsoft = GetRoots("Microsoft");

    /// <summary>
    ///     Nations Technologies Inc
    /// </summary>
    public static readonly byte[][] Nationz = GetRoots("Nationz");

    /// <summary>
    ///     Nuvoton Technology
    /// </summary>
    public static readonly byte[][] NuvotonTechnology = GetRoots("NuvotonTechnology");

    /// <summary>
    ///     STMicroelectronics International NV
    /// </summary>
    public static readonly byte[][] STMicroelectronics = GetRoots("STMicroelectronics");

    private static byte[][] GetRoots(string vendor)
    {
        const string rootCertificatesDirectory = "RootCertificates";

        var tpmRootsNamespace = typeof(DefaultTpmManufacturerVerifier).Namespace ?? "";
        var result = new UniqueByteArraysCollection();
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

            if (parts.Count == 0)
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
        }

        if (result.Count == 0)
        {
            throw new InvalidOperationException($"There is no embedded certificates for vendor: {vendor}");
        }

        return result.ToArray();
    }
}
