using System.Linq;
using System.Reflection;
using NUnit.Framework;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

public class DefaultTpmManufacturerVerifierTests
{
    // vendors with embedded root certificates of their own
    [TestCase(TpmManufacturers.AMD)]
    [TestCase(TpmManufacturers.Atmel)]
    [TestCase(TpmManufacturers.Infineon)]
    [TestCase(TpmManufacturers.Intel)]
    [TestCase(TpmManufacturers.Microsoft)]
    [TestCase(TpmManufacturers.Nationz)]
    [TestCase(TpmManufacturers.NuvotonTechnology)]
    [TestCase(TpmManufacturers.STMicroelectronics)]
    // vendors added to the TCG TPM Vendor ID Registry after Version 1.06 Revision 0.94 (the revision the library used before Version 1.08)
    [TestCase(TpmManufacturers.Arm)]
    [TestCase(TpmManufacturers.NSING)]
    [TestCase(TpmManufacturers.SecEdge)]
    [TestCase(TpmManufacturers.Wisekey)]
    // identifier corrected to the uppercase form mandated by the EK Credential Profile
    [TestCase(TpmManufacturers.IBM)]
    public void IsValid_ReturnsRootCertificates_WhenManufacturerIsKnown(string tpmManufacturer)
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        var result = verifier.IsValid(tpmManufacturer);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok, Is.Not.Null);
            Assert.That(result.Ok, Is.Not.Empty);
        });
    }

    [Test]
    public void IsValid_KnowsEveryVendorOfTheRegistry()
    {
        // TCG TPM Vendor ID Registry 1.08, Table 2: 30 vendors; every TpmManufacturers constant must be known to the verifier
        var verifier = new DefaultTpmManufacturerVerifier();
        var identifiers = typeof(TpmManufacturers)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(static x => x.IsLiteral)
            .Select(static x => (string) x.GetRawConstantValue()!)
            .ToArray();

        Assert.That(identifiers, Has.Length.EqualTo(30));
        Assert.Multiple(() =>
        {
            foreach (var identifier in identifiers)
            {
                var result = verifier.IsValid(identifier);
                Assert.That(result.HasError, Is.False, identifier);
                Assert.That(result.Ok, Is.Not.Empty, identifier);
            }
        });
    }

    [Test]
    public void IsValid_ReturnsVendorRoots_WhenVendorHasEmbeddedRoots()
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        Assert.Multiple(() =>
        {
            Assert.That(verifier.IsValid(TpmManufacturers.AMD).Ok, Is.EquivalentTo(TpmRoots.AMD));
            Assert.That(verifier.IsValid(TpmManufacturers.Atmel).Ok, Is.EquivalentTo(TpmRoots.Atmel));
            Assert.That(verifier.IsValid(TpmManufacturers.Infineon).Ok, Is.EquivalentTo(TpmRoots.Infineon));
            Assert.That(verifier.IsValid(TpmManufacturers.Intel).Ok, Is.EquivalentTo(TpmRoots.Intel));
            Assert.That(verifier.IsValid(TpmManufacturers.Microsoft).Ok, Is.EquivalentTo(TpmRoots.Microsoft));
            Assert.That(verifier.IsValid(TpmManufacturers.Nationz).Ok, Is.EquivalentTo(TpmRoots.Nationz));
            Assert.That(verifier.IsValid(TpmManufacturers.NuvotonTechnology).Ok, Is.EquivalentTo(TpmRoots.NuvotonTechnology));
            Assert.That(verifier.IsValid(TpmManufacturers.STMicroelectronics).Ok, Is.EquivalentTo(TpmRoots.STMicroelectronics));
        });
    }

    [Test]
    public void IsValid_ReturnsMicrosoftRoots_WhenVendorHasNoEmbeddedRoots()
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        var result = verifier.IsValid(TpmManufacturers.Wisekey);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok, Is.EquivalentTo(TpmRoots.Microsoft));
        });
    }

    // the registry prints the IBM identifier in lowercase, the EK Credential Profile mandates uppercase hexadecimal digits - both spellings are accepted
    [TestCase("id:49424d00")]
    [TestCase("id:49424D00")]
    [TestCase("id:414d4400")]
    public void IsValid_IgnoresCaseOfHexadecimalDigits(string tpmManufacturer)
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        var result = verifier.IsValid(tpmManufacturer);

        Assert.That(result.HasError, Is.False);
    }

    // FIDO conformance tools, TCG simulator / test identifiers (Table 3), malformed values,
    // a prefix other than the lowercase "id:" of the EK Credential Profile (§3.1.2)
    [TestCase("ID:414D4400")]
    [TestCase("Id:414D4400")]
    [TestCase("iD:414D4400")]
    [TestCase("id:FFFFF1D0")]
    [TestCase("id:53494D30")]
    [TestCase("id:54535430")]
    [TestCase("414D4400")]
    [TestCase("id:414D44")]
    [TestCase("AMD")]
    [TestCase("")]
    public void IsValid_Fails_WhenManufacturerIsUnknown(string tpmManufacturer)
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        var result = verifier.IsValid(tpmManufacturer);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void IsValid_Fails_WhenManufacturerIsNull()
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        var result = verifier.IsValid(null!);

        Assert.That(result.HasError, Is.True);
    }
}
