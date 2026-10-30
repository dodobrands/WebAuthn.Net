using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;

// End-to-end tests of DefaultTpmAttestationStatementVerifier.VerifyAsync: every attestation is built from scratch by TpmAttestationBuilder,
// valid in every respect except the one rule a test breaks, so a test fails only if the check it names is missing.
public class DefaultTpmAttestationStatementVerifierVerifyAsyncTests
{
    private static readonly string[] ServerAuthenticationOnly = { "1.3.6.1.5.5.7.3.1" };

    // ---------------------------------------------------------------------------------------------
    // Positive

    [TestCase((ushort) 0x0003)] // TPM_ECC_NIST_P256
    [TestCase((ushort) 0x0004)] // TPM_ECC_NIST_P384
    [TestCase((ushort) 0x0005)] // TPM_ECC_NIST_P521
    public async Task VerifyAsync_Succeeds_ForEccCredentialKey(ushort curve)
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder { Curve = curve }.Build();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.Tpm));
            Assert.That(result.Ok.AttestationType, Is.EqualTo(AttestationType.AttCa));
            Assert.That(result.Ok.AttestationTrustPath, Is.EqualTo(attestation.AttStmt.X5C));
            // the root of the FIDO Metadata Service entry for the aaguid: the AIK certificate doesn't certify the aaguid, so the embedded roots of the manufacturer aren't acceptable
            Assert.That(result.Ok.AttestationRootCertificates, Is.EquivalentTo(new[] { TpmAttestationBuilder.MetadataRoot }));
            Assert.That(verifier.FakeCounters.AttestationStatementAnomalies, Is.Empty);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [TestCase(0u)] // the default exponent 2^16 + 1
    [TestCase(65537u)] // the default exponent, written explicitly
    [TestCase(65539u)]
    public async Task VerifyAsync_Succeeds_ForRsaCredentialKey(uint exponent)
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { RsaCredentialKey = true, RsaExponent = exponent }.Build());

        Assert.That(result.HasError, Is.False);
    }

    [TestCase((ushort) 0x0004)] // TPM_ALG_SHA1
    [TestCase((ushort) 0x000B)] // TPM_ALG_SHA256
    [TestCase((ushort) 0x000C)] // TPM_ALG_SHA384
    [TestCase((ushort) 0x000D)] // TPM_ALG_SHA512
    public async Task VerifyAsync_Succeeds_WhenNameIsComputedWithNameAlgOfPubArea(ushort nameAlg)
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { NameAlg = nameAlg }.Build());

        Assert.That(result.HasError, Is.False);
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenAikIsAnEcdsaKey()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { EcdsaAik = true }.Build());

        Assert.That(result.HasError, Is.False);
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenAaguidExtensionMatchesAuthenticatorData()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { AaguidExtension = TpmAttestationBuilder.Aaguid }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            // the AIK certificate certifies the aaguid, so the embedded roots of the manufacturer named in it (id:414D4400 - AMD) are acceptable as well
            Assert.That(result.Ok!.AttestationRootCertificates, Is.EquivalentTo(TpmRoots.AMD.Append(TpmAttestationBuilder.MetadataRoot)));
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Step 2: the public key in pubArea is the credential public key

    [Test]
    public async Task VerifyAsync_Fails_WhenCredentialPublicKeyDiffersFromPubArea()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { MismatchedCoseKey = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not identical to the credential public key");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenCredentialPointIsNotOnTheCurve()
    {
        // ECDsa.Create throws CryptographicException for a point that is not on the curve; the verifier turns it into a failure
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder { OffCurveCredentialPoint = true }.Build();

        var hasError = false;
        await Assert.DoesNotThrowAsync(async () => hasError = (await verifier.VerifyAsync(attestation)).HasError);
        Assert.That(hasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenPubAreaIsInvalid()
    {
        // x509sign SET: TPM2_Sign() refuses such a key, so it can never sign an assertion
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { ObjectAttributes = TpmAttestationBuilder.EccObjectAttributes | (1u << 19) }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'pubArea' of the TPM attestation statement is not a valid TPMT_PUBLIC");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Step 4: integrity of certInfo

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CIsEmpty()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { EmptyX5C = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'x5c' of the TPM attestation statement is empty");
        });
    }

    [TestCase(-2)] // before NotBefore
    [TestCase(31)] // after NotAfter
    public async Task VerifyAsync_Fails_WhenAikCertificateIsNotValidAtTheCurrentTime(int days)
    {
        var verifier = new TestTpmAttestationStatementVerifier(TpmAttestationBuilder.Now.AddDays(days));

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder().Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not valid at the current time");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAikCertificateIsNotVersion3()
    {
        // X.509 v2 (the version field holds 1); macOS already refuses to load a v2 certificate with extensions, other platforms leave it to the version check
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { CertificateVersion = 1 }.Build());

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAikSubjectIsNotEmpty()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { Subject = new X500DistinguishedName("CN=AIK").RawData }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "TPM Attestation Statement Certificate Requirements: subject");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAikCertificateContainsAnExtensionTwice()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { DuplicateExtendedKeyUsage = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "TPM Attestation Statement Certificate Requirements: unique extensions");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenSubjectAlternativeNameIsMissing()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { OmitSubjectAlternativeName = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "TPM Attestation Statement Certificate Requirements: subject alternative name");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenTpmModelIsEmpty()
    {
        // EK Credential Profile 2.7 §3.1.2: UTF8String (SIZE (1..STRMAX))
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { TpmModel = string.Empty }.Build());

        Assert.That(result.HasError, Is.True);
    }

    [TestCase("id:FFFFF1D0")] // the FIDO conformance tools - not in the TCG TPM Vendor ID Registry
    [TestCase("id:58595A20")] // "XYZ " - the TCG reference implementation simulator
    [TestCase("ID:414D4400")] // AMD with an uppercase prefix (EK Credential Profile 2.7 §3.1.2: lowercase "id:")
    public async Task VerifyAsync_Fails_AndReportsAnomaly_WhenManufacturerIsUnknown(string manufacturer)
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { TpmManufacturer = manufacturer }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.AikCertificateManufacturerUnknown, false);
            AssertWarning(verifier, $"The TPMManufacturer '{manufacturer}' of the AIK certificate is not a vendor identifier known to the library");
        });
    }

    [Test]
    public async Task VerifyAsync_TruncatesUnknownManufacturer_InLogMessage()
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var manufacturer = "id:" + new string('A', 200);

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { TpmManufacturer = manufacturer }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"The TPMManufacturer '{manufacturer[..64]}...' of the AIK certificate");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenExtendedKeyUsageIsMissing()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { ExtendedKeyUsages = null }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "TPM Attestation Statement Certificate Requirements: extended key usage");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenExtendedKeyUsageLacksAikCertificateOid()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { ExtendedKeyUsages = ServerAuthenticationOnly }.Build());

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenExtendedKeyUsageIsMalformed()
    {
        // SEQUENCE { OBJECT IDENTIFIER with a truncated content } - decoded lazily by X509EnhancedKeyUsageExtension, which throws CryptographicException
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder { ExtendedKeyUsageValue = new byte[] { 0x30, 0x02, 0x06, 0x05 } }.Build();

        var hasError = false;
        await Assert.DoesNotThrowAsync(async () => hasError = (await verifier.VerifyAsync(attestation)).HasError);
        Assert.That(hasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenBasicConstraintsIsMissing()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { BasicConstraintsCa = null }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "TPM Attestation Statement Certificate Requirements: basic constraints");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenBasicConstraintsSaysCa()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { BasicConstraintsCa = true }.Build());

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenBasicConstraintsIsMalformed()
    {
        // SEQUENCE { BOOLEAN without content } - decoded lazily by X509BasicConstraintsExtension, which throws CryptographicException
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder { BasicConstraintsValue = new byte[] { 0x30, 0x02, 0x01, 0x01 } }.Build();

        var hasError = false;
        await Assert.DoesNotThrowAsync(async () => hasError = (await verifier.VerifyAsync(attestation)).HasError);
        Assert.That(hasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAaguidExtensionIsCritical()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { AaguidExtension = TpmAttestationBuilder.Aaguid, AaguidExtensionCritical = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "The id-fido-gen-ce-aaguid extension of the AIK certificate is invalid");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAaguidExtensionDiffersFromAuthenticatorData()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { AaguidExtension = Guid.Parse("00000000-0000-0000-0000-000000000001") }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "does not match the aaguid in the authenticator data");
        });
    }

    [TestCase("040F000102030405060708090A0B0C0D0E")] // a 15-byte OCTET STRING
    [TestCase("0410000102030405060708090A0B0C0D0E0F00")] // a trailing byte after the OCTET STRING
    [TestCase("24120410000102030405060708090A0B0C0D0E0F")] // a constructed (BER) OCTET STRING
    [TestCase("048110000102030405060708090A0B0C0D0E0F")] // a non-minimal length (BER)
    [TestCase("000102030405060708090A0B0C0D0E0F")] // the AAGUID without its inner OCTET STRING wrapper
    public async Task VerifyAsync_Fails_WhenAaguidExtensionIsMalformed(string extensionValueHex)
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { AaguidExtensionValue = Convert.FromHexString(extensionValueHex) }.Build());

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenSignatureIsInvalid()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { CorruptSignature = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not a valid signature over 'certInfo'");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenAikPublicKeyIsNotOnTheCurve()
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder { EcdsaAik = true, AikSubjectPublicKeyInfo = TpmAttestationBuilder.OffCurveP256SubjectPublicKeyInfo() }.Build();

        var hasError = false;
        await Assert.DoesNotThrowAsync(async () => hasError = (await verifier.VerifyAsync(attestation)).HasError);
        Assert.That(hasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenAikPublicKeyHasExplicitCurveParameters()
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var attestation = new TpmAttestationBuilder { EcdsaAik = true, AikSubjectPublicKeyInfo = TpmAttestationBuilder.ExplicitCurveP256SubjectPublicKeyInfo() }.Build();

        var hasError = false;
        await Assert.DoesNotThrowAsync(async () => hasError = (await verifier.VerifyAsync(attestation)).HasError);
        Assert.That(hasError, Is.True);
    }

    // ---------------------------------------------------------------------------------------------
    // Step 5: certInfo is valid

    [Test]
    public async Task VerifyAsync_Fails_WhenExtraDataIsNotTheHashOfAttToBeSigned()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { WrongExtraData = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'extraData' of the 'certInfo' of the TPM attestation statement is not the hash of attToBeSigned");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenNameAlgorithmDiffersFromNameAlgOfPubArea()
    {
        // name = TPM_ALG_SHA3_256 || SHA-256(pubArea) for a pubArea whose nameAlg is TPM_ALG_SHA256: a well-formed 34-byte Name whose digest matches,
        // so only the comparison of the hash algorithms can reject it
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { NameAlgIdInCertInfo = 0x0027 }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not a digest computed with the nameAlg of the 'pubArea'");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenNameIsEmpty()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { EmptyNameInCertInfo = true }.Build());

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenNameDigestIsNotTheDigestOfPubArea()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { CorruptNameDigest = true }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not the Name of the 'pubArea'");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_AndReportsAnomaly_WhenNameAlgCannotBeComputed()
    {
        // TPM_ALG_SM3_256 is a valid nameAlg, but .NET cannot compute SM3, so the Name cannot be verified
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { NameAlg = 0x0012 }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.PubAreaNameAlgNotSupported, false);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Tolerated anomalies: the attestation statement is accepted, the deviation is logged and counted

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenReservedObjectAttributeBit3IsSet()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { ObjectAttributes = TpmAttestationBuilder.EccObjectAttributes | (1u << 3) }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.PubAreaReservedBit3, true);
            AssertWarning(verifier, "reserved TPMA_OBJECT bit 3 SET");
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenSubjectAlternativeNameIsNotCritical()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { SubjectAlternativeNameCritical = false }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.AikCertificateSanNotCritical, true);
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenManufacturerHexDigitsAreLowercase()
    {
        var verifier = new TestTpmAttestationStatementVerifier();

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { TpmManufacturer = "id:414d4400" }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.AikCertificateManufacturerNotCanonical, true);
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenSubjectAlternativeNameIsBareRdnSequence()
    {
        // the layout of the certificate example of the EK Credential Profile (2.5r2 Appendix A, 2.7 Appendix B)
        var verifier = new TestTpmAttestationStatementVerifier();
        var san = TpmAttestationBuilder.Rdns(
            TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmManufacturerOid, "id:414D4400"),
            TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmModelOid, "AMD"),
            TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmVersionOid, "id:00030001"));
        var attestation = new TpmAttestationBuilder { SubjectAlternativeName = san }.Build();
        // Apple's certificate import refuses a certificate whose Subject Alternative Name is not GeneralNames ("Unknown format in import"),
        // so on macOS such an AIK certificate never reaches the parser; OpenSSL (Linux) and CNG (Windows) load it.
        var platformLoadsCertificate = X509CertificateInMemoryLoader.TryLoad(attestation.AttStmt.X5C[0], out var certificate);
        certificate?.Dispose();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            if (platformLoadsCertificate)
            {
                Assert.That(result.HasError, Is.False);
                AssertAnomaly(verifier, TpmAttestationStatementAnomalies.AikCertificateSanWithoutGeneralNames, true);
            }
            else
            {
                Assert.That(result.HasError, Is.True);
                AssertWarning(verifier, "Failed to load a certificate from the 'x5c' of the TPM attestation statement");
            }
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenSubjectAlternativeNameContainsHardwareModuleName()
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var san = TpmAttestationBuilder.SanWithDirectoryName(
            TpmAttestationBuilder.Rdns(
                TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmManufacturerOid, "id:414D4400"),
                TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmModelOid, "AMD"),
                TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmVersionOid, "id:00030001")),
            new[] { TpmAttestationBuilder.HardwareModuleNameOtherName() });

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { SubjectAlternativeName = san }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.AikCertificateSanHardwareModuleName, true);
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_AndReportsAnomaly_WhenSubjectAlternativeNameRepeatsAnAttribute()
    {
        var verifier = new TestTpmAttestationStatementVerifier();
        var san = TpmAttestationBuilder.SanWithDirectoryName(TpmAttestationBuilder.Rdns(
            TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmManufacturerOid, "id:414D4400"),
            TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmModelOid, "AMD"),
            TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmVersionOid, "id:00030001"),
            TpmAttestationBuilder.Atv(TpmAttestationBuilder.TpmModelOid, "AMD")));

        var result = await verifier.VerifyAsync(new TpmAttestationBuilder { SubjectAlternativeName = san }.Build());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            AssertAnomaly(verifier, TpmAttestationStatementAnomalies.AikCertificateSanDuplicateAttribute, true);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static void AssertAnomaly(TestTpmAttestationStatementVerifier verifier, string anomaly, bool tolerated)
    {
        Assert.That(
            verifier.FakeCounters.AttestationStatementAnomalies,
            Has.Exactly(1).EqualTo(new FakeAttestationStatementAnomaly(TpmAttestationStatementAnomalies.Format, anomaly, tolerated)),
            $"expected exactly one '{anomaly}' anomaly (tolerated: {tolerated})");
    }

    private static void AssertWarning(TestTpmAttestationStatementVerifier verifier, string messagePart)
    {
        Assert.That(
            verifier.FakeLogger.Entries.Where(x => x.Level == LogLevel.Warning).Select(static x => x.Message),
            Has.Some.Contains(messagePart),
            $"expected a Warning containing '{messagePart}'");
    }
}
