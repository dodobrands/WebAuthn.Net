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
    // vendors added in TCG TPM Vendor ID Registry 1.07 / 1.08
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
    public void IsValid_ReturnsVendorRoots_WhenVendorHasEmbeddedRoots()
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        var result = verifier.IsValid(TpmManufacturers.AMD);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok, Is.EquivalentTo(TpmRoots.AMD));
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

    // the registry prints the IBM identifier in lowercase, the EK Credential Profile mandates uppercase - both spellings are accepted
    [TestCase("id:49424d00")]
    [TestCase("id:49424D00")]
    [TestCase("ID:414D4400")]
    [TestCase("id:414d4400")]
    public void IsValid_IgnoresCase_WhenComparingManufacturerIdentifiers(string tpmManufacturer)
    {
        var verifier = new DefaultTpmManufacturerVerifier();

        var result = verifier.IsValid(tpmManufacturer);

        Assert.That(result.HasError, Is.False);
    }

    // FIDO conformance tools, TCG simulator / test identifiers (Table 3), malformed values
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
}
