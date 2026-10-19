using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

public class TpmRootsTests
{
    private static IEnumerable<TestCaseData> VendorRootSets()
    {
        foreach (var field in RootSetFields())
        {
            yield return new TestCaseData(field.Name, (byte[][]) field.GetValue(null)!).SetArgDisplayNames(field.Name);
        }
    }

    private static IEnumerable<TestCaseData> EmbeddedRoots()
    {
        foreach (var field in RootSetFields())
        {
            var roots = (byte[][]) field.GetValue(null)!;
            for (var i = 0; i < roots.Length; i++)
            {
                yield return new TestCaseData(roots[i]).SetArgDisplayNames($"{field.Name}[{i}]");
            }
        }
    }

    private static IEnumerable<FieldInfo> RootSetFields()
    {
        return typeof(TpmRoots)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(static x => x.FieldType == typeof(byte[][]));
    }

    [Test]
    public void Microsoft_HoldsTheTwoMicrosoftTpmRoots()
    {
        // Microsoft TPM Root Certificate Authority 2014 and Microsoft Pluton Root CA 2021
        Assert.That(TpmRoots.Microsoft, Has.Length.EqualTo(2));
    }

    // every vendor folder (RootCertificates/<Vendor>) holds the vendor's own roots plus the two Microsoft TPM roots the Windows AIK certificates chain to
    [TestCaseSource(nameof(VendorRootSets))]
    public void EveryVendorRootSet_ContainsTheMicrosoftRoots(string vendor, byte[][] roots)
    {
        Assert.Multiple(() =>
        {
            foreach (var microsoftRoot in TpmRoots.Microsoft)
            {
                Assert.That(roots.Any(x => x.SequenceEqual(microsoftRoot)), Is.True, vendor);
            }

            if (vendor != nameof(TpmRoots.Microsoft))
            {
                Assert.That(roots, Has.Length.GreaterThan(TpmRoots.Microsoft.Length), vendor);
            }
        });
    }

    // the embedded roots are maintained from the Microsoft TrustedTpm package: only CA certificates that have not expired are kept
    [TestCaseSource(nameof(EmbeddedRoots))]
    public void EveryEmbeddedRoot_IsAnUnexpiredCaCertificate(byte[] root)
    {
        var parsed = X509CertificateInMemoryLoader.TryLoad(root, out var certificate);
        Assert.That(parsed, Is.True);
        using var loaded = certificate!;

        var basicConstraints = loaded.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        var keyUsage = loaded.Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        Assert.Multiple(() =>
        {
            Assert.That(basicConstraints, Is.Not.Null, loaded.Subject);
            Assert.That(basicConstraints!.CertificateAuthority, Is.True, loaded.Subject);
            Assert.That(keyUsage, Is.Not.Null, loaded.Subject);
            Assert.That(keyUsage!.KeyUsages & X509KeyUsageFlags.KeyCertSign, Is.EqualTo(X509KeyUsageFlags.KeyCertSign), loaded.Subject);
            Assert.That(loaded.NotAfter.ToUniversalTime(), Is.GreaterThan(DateTime.UtcNow), loaded.Subject);
        });
    }
}
