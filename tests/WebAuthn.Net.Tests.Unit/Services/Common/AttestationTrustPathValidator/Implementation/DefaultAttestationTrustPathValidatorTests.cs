using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;

public class DefaultAttestationTrustPathValidatorTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    // ---------------------------------------------------------------------------------------------
    // WebAuthn L3 §6.5.2: the attestation trust path "is either empty (in case of self attestation), or a set of X.509 certificates";
    // the packed self attestation (§8.2) and the none attestation statement format (§8.7) return an empty trust path, and §7.1 step 24 assesses them by the policy of the Relying Party only

    [TestCase(AttestationStatementFormat.Packed, AttestationType.Self)]
    [TestCase(AttestationStatementFormat.None, AttestationType.None)]
    public async Task IsValidAsync_ReturnsTrue_ForSelfAndNoAttestationWithoutTrustPath(AttestationStatementFormat fmt, AttestationType attestationType)
    {
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = await validator.IsValidAsync(new(fmt, attestationType, null, null), CancellationToken.None);

        Assert.That(isValid, Is.True);
    }

    [TestCase(AttestationStatementFormat.Packed, AttestationType.Self)]
    [TestCase(AttestationStatementFormat.None, AttestationType.None)]
    public async Task IsValidAsync_ReturnsFalse_ForSelfAndNoAttestationWithSelfSignedCertificateAsTrustPath(AttestationStatementFormat fmt, AttestationType attestationType)
    {
        // a self-signed certificate made the self attestation valid before: it is not a trust path that the specification defines for these attestation types
        using var certificate = CreateSelfSigned("CN=WebAuthn.Net Self-Signed", false);
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = await validator.IsValidAsync(new(fmt, attestationType, new[] { certificate.RawData }, null), CancellationToken.None);

        Assert.That(isValid, Is.False);
    }

    [TestCase(AttestationStatementFormat.Packed, AttestationType.Self)]
    [TestCase(AttestationStatementFormat.None, AttestationType.None)]
    public async Task IsValidAsync_ReturnsFalse_ForSelfAndNoAttestationWhoseTrustPathIsTheirRootCertificate(AttestationStatementFormat fmt, AttestationType attestationType)
    {
        // the self attestation whose single certificate was its single root certificate (as the packed verifier returned for the "basic_surrogate" metadata) was valid before
        using var certificate = CreateSelfSigned("CN=WebAuthn.Net Self-Signed", false);
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = await validator.IsValidAsync(new(fmt, attestationType, new[] { certificate.RawData }, new UniqueByteArraysCollection(new[] { certificate.RawData })), CancellationToken.None);

        Assert.That(isValid, Is.False);
    }

    // ---------------------------------------------------------------------------------------------
    // The other attestation types: the trust path must chain up to an acceptable root certificate (§7.1 step 24)

    [Test]
    public async Task IsValidAsync_ReturnsTrue_ForBasicAttestation_WhenTrustPathChainsUpToRootCertificate()
    {
        using var root = CreateSelfSigned("CN=WebAuthn.Net Root", true);
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest("CN=WebAuthn.Net Attestation", leafKey, HashAlgorithmName.SHA256).Create(root, Now.AddDays(-1), Now.AddDays(30), new byte[] { 1, 2, 3, 4 });
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = await validator.IsValidAsync(new(AttestationStatementFormat.Packed, AttestationType.Basic, new[] { leaf.RawData }, new UniqueByteArraysCollection(new[] { root.RawData })), CancellationToken.None);

        Assert.That(isValid, Is.True);
    }

    [Test]
    public async Task IsValidAsync_ReturnsFalse_ForBasicAttestationWithoutTrustPath()
    {
        using var root = CreateSelfSigned("CN=WebAuthn.Net Root", true);
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());

        var isValid = await validator.IsValidAsync(new(AttestationStatementFormat.Packed, AttestationType.Basic, null, new UniqueByteArraysCollection(new[] { root.RawData })), CancellationToken.None);

        Assert.That(isValid, Is.False);
    }

    // ---------------------------------------------------------------------------------------------
    // The certificate revocation status list of the Android attestation keys covers every chain that ends at a root certificate of the key attestation of Google,
    // whatever the attestation statement format: an Android attestation key can sign any certificate, such as the attestation certificate of a "packed" attestation statement.
    // The chains here end at the root certificate of a test hierarchy, which the validator takes for a root certificate of the key attestation of Google.

    [TestCase(0, AndroidAttestationKeyHierarchy.AttestationCertificateSerialNumber)]
    [TestCase(1, AndroidAttestationKeyHierarchy.AttestationKeySerialNumber)]
    [TestCase(2, AndroidAttestationKeyHierarchy.IntermediateSerialNumber)]
    [TestCase(3, AndroidAttestationKeyHierarchy.RootSerialNumber)]
    public async Task IsValidAsync_ReturnsFalse_WhenAnyCertificateOfChainToGoogleRootIsInStatusList(int index, string serialNumber)
    {
        // the root certificate is not in the trust path, but it is in the built chain
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        var validator = CreateValidatorWithGoogleRoot(hierarchy.Root);
        validator.FakeStatusStorage.StatusList = FakeAndroidKeyAttestationStatusStorage.With(serialNumber);

        var isValid = await validator.IsValidAsync(CreatePackedAttestation(hierarchy, hierarchy.Root), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.False);
            Assert.That(validator.FakeStatusCounters.CertificatesListed, Is.EqualTo(1));
            Assert.That(
                validator.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).EqualTo($"The certificate #{index} (serial number '{serialNumber}') of the certificate chain of the 'Packed' attestation statement is in the certificate revocation status list of the Android attestation keys with the status 'Revoked' and the reason 'KeyCompromise'"));
        });
    }

    [TestCase(AttestationStatementFormat.Packed, AttestationType.Basic)]
    [TestCase(AttestationStatementFormat.AndroidKey, AttestationType.Basic)]
    [TestCase(AttestationStatementFormat.Tpm, AttestationType.AttCa)]
    public async Task IsValidAsync_ReturnsFalse_WhenCertificateOfChainToGoogleRootIsInStatusList_WhateverTheFormat(AttestationStatementFormat fmt, AttestationType attestationType)
    {
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        var validator = CreateValidatorWithGoogleRoot(hierarchy.Root);
        validator.FakeStatusStorage.StatusList = FakeAndroidKeyAttestationStatusStorage.With(AndroidAttestationKeyHierarchy.AttestationKeySerialNumber);
        var packedAttestation = CreatePackedAttestation(hierarchy, hierarchy.Root);

        var isValid = await validator.IsValidAsync(new(fmt, attestationType, packedAttestation.AttestationTrustPath, packedAttestation.AttestationRootCertificates), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.False);
            Assert.That(validator.FakeStatusCounters.CertificatesListed, Is.EqualTo(1));
            Assert.That(
                validator.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).EqualTo($"The certificate #1 (serial number '{AndroidAttestationKeyHierarchy.AttestationKeySerialNumber}') of the certificate chain of the '{fmt}' attestation statement is in the certificate revocation status list of the Android attestation keys with the status 'Revoked' and the reason 'KeyCompromise'"));
        });
    }

    [Test]
    public async Task IsValidAsync_ReturnsFalse_WhenChainEndsAtGoogleRootAndNoStatusListIsAvailable()
    {
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        var validator = CreateValidatorWithGoogleRoot(hierarchy.Root);
        validator.FakeStatusStorage.StatusList = null;

        var isValid = await validator.IsValidAsync(CreatePackedAttestation(hierarchy, hierarchy.Root), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.False);
            Assert.That(validator.FakeStatusCounters.ChecksWithoutStatusList, Is.EqualTo(1));
            Assert.That(
                validator.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).EqualTo("The certificate revocation status list of the Android attestation keys is not available, so the 'Packed' attestation statement, whose certificate chain ends at a root certificate of the key attestation of Google, is rejected"));
        });
    }

    [Test]
    public async Task IsValidAsync_ReturnsTrue_WhenNoCertificateOfChainToGoogleRootIsInStatusList()
    {
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        var validator = CreateValidatorWithGoogleRoot(hierarchy.Root);
        validator.FakeStatusStorage.StatusList = FakeAndroidKeyAttestationStatusStorage.With("1228286566665971148");

        var isValid = await validator.IsValidAsync(CreatePackedAttestation(hierarchy, hierarchy.Root), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.True);
            Assert.That(validator.FakeStatusCounters.CertificatesListed, Is.Zero);
            Assert.That(validator.FakeLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task IsValidAsync_RecognizesRootCertificateOfGoogle_ByItsKey()
    {
        // the chain ends at another root certificate with the same key (as Google issues its root certificate again from time to time)
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        var validator = CreateValidatorWithGoogleRoot(hierarchy.Root);
        validator.FakeStatusStorage.StatusList = FakeAndroidKeyAttestationStatusStorage.With(AndroidAttestationKeyHierarchy.AttestationKeySerialNumber);

        var isValid = await validator.IsValidAsync(CreatePackedAttestation(hierarchy, hierarchy.IssueRootAgain("61")), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.False);
            Assert.That(validator.FakeStatusCounters.CertificatesListed, Is.EqualTo(1));
        });
    }

    [Test]
    public async Task IsValidAsync_ReturnsTrue_WhenChainEndsAtOtherRoot_EvenIfItsCertificateIsInStatusList()
    {
        // the status list covers only the chains of the key attestation of Google: serial numbers are unique per issuer only
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());
        validator.FakeStatusStorage.StatusList = FakeAndroidKeyAttestationStatusStorage.With(AndroidAttestationKeyHierarchy.AttestationKeySerialNumber);

        var isValid = await validator.IsValidAsync(CreatePackedAttestation(hierarchy, hierarchy.Root), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.True);
            Assert.That(validator.FakeStatusCounters.CertificatesListed, Is.Zero);
            Assert.That(validator.FakeLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task IsValidAsync_ReturnsTrue_WhenChainEndsAtOtherRootAndNoStatusListIsAvailable()
    {
        // the attestation statements of other authenticators don't depend on the status list of the Android attestation keys
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());
        validator.FakeStatusStorage.StatusList = null;

        var isValid = await validator.IsValidAsync(CreatePackedAttestation(hierarchy, hierarchy.Root), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.True);
            Assert.That(validator.FakeStatusCounters.ChecksWithoutStatusList, Is.Zero);
            Assert.That(validator.FakeLogger.Entries, Is.Empty);
        });
    }

    private static TestAttestationTrustPathValidator CreateValidatorWithGoogleRoot(byte[] googleRoot)
    {
        var validator = new TestAttestationTrustPathValidator(new OptionsMonitorStub());
        validator.GoogleRoots.Add(googleRoot);
        return validator;
    }

    // a "packed" attestation whose attestation certificate is signed with the attestation key of the hierarchy, and whose acceptable root certificate is the given one
    private static VerifiedAttestationStatement CreatePackedAttestation(AndroidAttestationKeyHierarchy hierarchy, byte[] rootCertificate)
    {
        using var attestationCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attestationCertificate = hierarchy.IssuePackedAttestationCertificate(attestationCertificateKey);
        return new(
            AttestationStatementFormat.Packed,
            AttestationType.Basic,
            new[] { attestationCertificate, hierarchy.AttestationKeyCertificate, hierarchy.Intermediate },
            new UniqueByteArraysCollection(new[] { rootCertificate }));
    }

    private static X509Certificate2 CreateSelfSigned(string subject, bool isCa)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        if (isCa)
        {
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        }

        return request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
    }

    private sealed class OptionsMonitorStub : IOptionsMonitor<WebAuthnOptions>
    {
        public WebAuthnOptions CurrentValue { get; } = new();

        public WebAuthnOptions Get(string? name)
        {
            return CurrentValue;
        }

        public IDisposable? OnChange(Action<WebAuthnOptions, string?> listener)
        {
            return null;
        }
    }
}
