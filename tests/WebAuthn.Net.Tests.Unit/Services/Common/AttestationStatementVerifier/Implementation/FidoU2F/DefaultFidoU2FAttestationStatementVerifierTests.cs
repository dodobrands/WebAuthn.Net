using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Models;
using WebAuthn.Net.Services.Serialization.Cose.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Static;
using static WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AttestationStatementVerifierTestHelpers;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F;

// Tests of DefaultFidoU2FAttestationStatementVerifier.VerifyAsync: every attestation is built from scratch (a self-signed P-256 attestation certificate signs the U2F registration data),
// valid in every respect except the one rule a test breaks, so a test fails only if the check it names is missing.
public class DefaultFidoU2FAttestationStatementVerifierTests
{
    // The attestation certificate of the committed FIDO U2F test vector (tests/WebAuthn.Net.Tests.Unit/TestVectors/FidoU2F: "Yubico U2F EE Serial 413943488"), which carries no Subject Key Identifier extension,
    // and the identifier the FIDO Metadata Service publishes for it in 'attestationCertificateKeyIdentifiers' (an entry of the committed blob.jwt): the RFC 5280 §4.2.1.2 method (1) hash of its public key.
    private const string YubicoU2FVectorCertificate =
        "MIICvTCCAaWgAwIBAgIEGKxGwDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNDEzOTQzNDg4MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeeo7LHxJcBBiIwzSP+tg5SkxcdSD8QC+hZ1rD4OXAwG1Rs3Ubs/K4+PzD4Hp7WK9Jo1MHr03s7y+kqjCrutOOqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQy2lIHo/3QDmT7AonKaFUqDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCXnQOX2GD4LuFdMRx5brr7Ivqn4ITZurTGG7tX8+a0wYpIN7hcPE7b5IND9Nal2bHO2orh/tSRKSFzBY5e4cvda9rAdVfGoOjTaCW6FZ5/ta2M2vgEhoz5Do8fiuoXwBa1XCp61JfIlPtx11PXm5pIS2w3bXI7mY0uHUMGvxAzta74zKXLslaLaSQibSKjWKt9h+SsXy4JGqcVefOlaQlJfXL1Tga6wcO0QTu6Xq+Uw7ZPNPnrpBrLauKDd202RlN4SP7ohL3d9bG6V5hUz/3OusNEBZUn5W3VmPj1ZnFavkMB3RkRMOa58MZAORJT4imAPzrvJ0vtv94/y71C6tZ5";

    private const string YubicoU2FVectorKeyIdentifier = "bdeb7f015a66e4c8448b414ffd41ca669bba6b4a";

    // ---------------------------------------------------------------------------------------------
    // Metadata lookup by the attestation certificate key identifier (FIDO Metadata Statement §3.1 'attestationCertificateKeyIdentifiers': RFC 5280 §4.2.1.2 method (1))

    [Test]
    public void TryComputeAttestationCertificateKeyIdentifier_ReturnsRfc5280Method1Hash_ForCommittedU2FVectorCertificate()
    {
        var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService());
        Assert.That(X509CertificateInMemoryLoader.TryLoad(Convert.FromBase64String(YubicoU2FVectorCertificate), out var certificate), Is.True);
        using (certificate)
        {
            var computed = verifier.ComputeKeyIdentifier(certificate!, out var keyIdentifier);

            Assert.Multiple(() =>
            {
                Assert.That(computed, Is.True);
                Assert.That(Convert.ToHexString(keyIdentifier!).ToLowerInvariant(), Is.EqualTo(YubicoU2FVectorKeyIdentifier));
                Assert.That(certificate!.Extensions.OfType<X509SubjectKeyIdentifierExtension>(), Is.Empty, "the vector certificate has no SKI extension: the identifier can only come from the public key");
            });
        }
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenMetadataIsFoundByComputedKeyIdentifier_AndCertificateHasNoSkiExtension()
    {
        var attestation = FidoU2FAttestation.Create();
        var metadata = new RecordingFidoMetadataSearchService().WithKeyIdentifier(attestation.Method1KeyIdentifier, RecordingFidoMetadataSearchService.Metadata(attestation.Root, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL));
        var verifier = new TestFidoU2FVerifier(metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.FidoU2F));
            Assert.That(result.Ok.AttestationType, Is.EqualTo(AttestationType.Basic));
            Assert.That(result.Ok.AttestationTrustPath, Is.EqualTo(attestation.AttStmt.X5C));
            Assert.That(result.Ok.AttestationRootCertificates, Is.EquivalentTo(new[] { attestation.Root }));
            Assert.That(metadata.AaguidLookups, Is.Empty);
            Assert.That(metadata.KeyIdentifierLookups, Is.EqualTo(new[] { Convert.ToHexString(attestation.Method1KeyIdentifier) }));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenMetadataIsFoundBySkiExtensionValue_AfterComputedKeyIdentifierIsNotFound()
    {
        // a vendor that computed the identifier with another method: the SKI extension value is tried after the method (1) hash
        var vendorIdentifier = Enumerable.Range(0, 20).Select(static x => (byte) (0xA0 + x)).ToArray();
        var attestation = FidoU2FAttestation.Create(subjectKeyIdentifier: vendorIdentifier);
        var metadata = new RecordingFidoMetadataSearchService().WithKeyIdentifier(vendorIdentifier, RecordingFidoMetadataSearchService.Metadata(attestation.Root, AuthenticatorAttestationType.ATTESTATION_ATTCA));
        var verifier = new TestFidoU2FVerifier(metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationType, Is.EqualTo(AttestationType.AttCa));
            Assert.That(metadata.KeyIdentifierLookups, Is.EqualTo(new[] { Convert.ToHexString(attestation.Method1KeyIdentifier), Convert.ToHexString(vendorIdentifier) }));
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenMetadataIsNotFoundByAnyKeyIdentifier()
    {
        var attestation = FidoU2FAttestation.Create();
        var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService());

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"no trusted metadata for the attestation certificate key identifier {Convert.ToHexString(attestation.Method1KeyIdentifier)}");
        });
    }

    [Test]
    public async Task VerifyAsync_UsesAaguidExtension_WhenAttCertCarriesOne()
    {
        var attestation = FidoU2FAttestation.Create(aaguidExtension: Aaguid);
        var metadata = new RecordingFidoMetadataSearchService().WithAaguid(Aaguid, RecordingFidoMetadataSearchService.Metadata(attestation.Root, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL));
        var verifier = new TestFidoU2FVerifier(metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(metadata.AaguidLookups, Is.EqualTo(new[] { Aaguid }));
            Assert.That(metadata.KeyIdentifierLookups, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The typed Subject Key Identifier extension is decoded lazily and is client-supplied, so a malformed value must fail, not throw

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenSubjectKeyIdentifierExtensionIsMalformed()
    {
        // SEQUENCE instead of OCTET STRING
        var attestation = FidoU2FAttestation.Create(rawSubjectKeyIdentifierExtension: new byte[] { 0x30, 0x00 });
        var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService());

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation));

        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            Assert.That(verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning), Is.Not.Empty);
        });
    }

    [Test]
    public void GetSubjectKeyIdentifierIfExists_Fails_WithoutException_WhenExtensionValueIsMalformed()
    {
        // the local guard of the verifier, independent of the certificate loader rejecting such certificates
        var attestation = FidoU2FAttestation.Create(rawSubjectKeyIdentifierExtension: new byte[] { 0x30, 0x00 });
        var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService());
        using var certificate = LoadWithPlatformLoader(attestation.AttStmt.X5C[0]);
        if (certificate is null)
        {
            Assert.Ignore("the platform refuses to load a certificate with a malformed Subject Key Identifier extension");
            return;
        }

        Result<byte[]?>? result = null;
        Assert.DoesNotThrow(() => result = verifier.GetSki(certificate));

        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            AssertWarning(verifier, "Subject Key Identifier extension of the attCert of the FIDO U2F attestation statement is malformed");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Step 2: the certificate public key must be an EC public key over the named P-256 curve

    [Test]
    public void IsValidPublicKeyParameters_ReturnsFalse_WithoutException_WhenCurveParametersAreExplicit()
    {
        // explicit parameters with the generator -G: a valid group that no named curve has, so ECCurve.Oid of the exported parameters is null
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bytes = BuildCertificate(issuerKey, "CN=WebAuthn.Net Explicit Curve", "CN=WebAuthn.Net Explicit Curve", ExplicitCurveNegatedGeneratorSubjectPublicKeyInfo(), Array.Empty<X509Extension>());
        if (!X509CertificateInMemoryLoader.TryLoad(bytes, out var certificate))
        {
            Assert.Ignore("the platform refuses to load a certificate with explicit curve parameters, so the verifier never sees such a key");
            return;
        }

        using (certificate)
        {
            var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService());
            var valid = true;
            Assert.DoesNotThrow(() => valid = verifier.IsValidKey(certificate, out _));
            Assert.That(valid, Is.False);
        }
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAttCertKeyIsNotP256()
    {
        var attestation = FidoU2FAttestation.Create(curve: ECCurve.NamedCurves.nistP384);
        var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService());

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not an Elliptic Curve public key over the named P-256 curve");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Steps 3-6

    [Test]
    public async Task VerifyAsync_Fails_WhenCredentialPublicKeyIsNotEc2()
    {
        using var rsa = RSA.Create(2048);
        var rsaParameters = rsa.ExportParameters(false);
        var attestation = FidoU2FAttestation.Create(credentialPublicKey: new CoseRsaKey(CoseAlgorithm.RS256, rsaParameters.Modulus!, rsaParameters.Exponent!));
        var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService());

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "credential public key of the FIDO U2F attestation statement is not an EC2 COSE key");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenSignatureIsInvalid()
    {
        var attestation = FidoU2FAttestation.Create(corruptSignature: true);
        var metadata = new RecordingFidoMetadataSearchService().WithKeyIdentifier(attestation.Method1KeyIdentifier, RecordingFidoMetadataSearchService.Metadata(attestation.Root, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL));
        var verifier = new TestFidoU2FVerifier(metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'sig' of the FIDO U2F attestation statement is not a valid signature");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenSignatureIsNotDer()
    {
        var attestation = FidoU2FAttestation.Create();
        var metadata = new RecordingFidoMetadataSearchService().WithKeyIdentifier(attestation.Method1KeyIdentifier, RecordingFidoMetadataSearchService.Metadata(attestation.Root, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL));
        var verifier = new TestFidoU2FVerifier(metadata);
        var garbageSignature = new FidoU2FAttestationStatement(new byte[] { 0xFF, 0x00, 0x01 }, attestation.AttStmt.X5C);

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation with { AttStmt = garbageSignature }));

        Assert.That(result!.HasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenMetadataListsOnlySurrogateAttestation()
    {
        var attestation = FidoU2FAttestation.Create();
        var metadata = new RecordingFidoMetadataSearchService().WithKeyIdentifier(attestation.Method1KeyIdentifier, RecordingFidoMetadataSearchService.Metadata(attestation.Root, AuthenticatorAttestationType.ATTESTATION_BASIC_SURROGATE));
        var verifier = new TestFidoU2FVerifier(metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "lists no attestation type that a FIDO U2F attestation statement can convey");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAttCertIsExpired()
    {
        var attestation = FidoU2FAttestation.Create();
        var verifier = new TestFidoU2FVerifier(new RecordingFidoMetadataSearchService(), Now.AddYears(2));

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "attCert of the FIDO U2F attestation statement is not valid at the current time");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static void AssertWarning(TestFidoU2FVerifier verifier, string messagePart)
    {
        Assert.That(
            verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
            Has.Some.Contains(messagePart),
            $"expected a Warning containing '{messagePart}'");
    }

    private sealed record FidoU2FAttestation(FidoU2FAttestationStatement AttStmt, AttestedAuthenticatorData AuthenticatorData, byte[] ClientDataHash, byte[] Root, byte[] Method1KeyIdentifier)
    {
        public static FidoU2FAttestation Create(
            byte[]? subjectKeyIdentifier = null,
            byte[]? rawSubjectKeyIdentifierExtension = null,
            Guid? aaguidExtension = null,
            ECCurve? curve = null,
            AbstractCoseKey? credentialPublicKey = null,
            bool corruptSignature = false)
        {
            using var attestationKey = ECDsa.Create(curve ?? ECCurve.NamedCurves.nistP256);
            var extensions = new System.Collections.Generic.List<X509Extension> { EndEntityBasicConstraints() };
            if (subjectKeyIdentifier is not null)
            {
                extensions.Add(new X509SubjectKeyIdentifierExtension(subjectKeyIdentifier, false));
            }

            if (rawSubjectKeyIdentifierExtension is not null)
            {
                extensions.Add(new X509Extension("2.5.29.14", rawSubjectKeyIdentifierExtension, false));
            }

            if (aaguidExtension.HasValue)
            {
                extensions.Add(new X509Extension("1.3.6.1.4.1.45724.1.1.4", new byte[] { 0x04, 0x10 }.Concat(aaguidExtension.Value.ToByteArray(true)).ToArray(), false));
            }

            // U2F attestation certificates are self-signed or issued by a vendor CA; the certificate itself is the only element of x5c and the metadata entry's root
            using var attCert = CreateSelfSigned("C=SE, O=WebAuthn.Net, OU=Authenticator Attestation, CN=WebAuthn.Net Test U2F Attestation", attestationKey, false, extensions.ToArray());
            using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var coseKey = credentialPublicKey ?? ToCoseEc2Key(credentialKey);
            var authenticatorData = CreateAuthenticatorData(Guid.Empty, coseKey);
            var clientDataHash = CreateClientDataHash();
            var credentialParameters = credentialKey.ExportParameters(false);
            // verificationData = 0x00 || rpIdHash || clientDataHash || credentialId || 0x04 || x || y
            var verificationData = new byte[] { 0x00 }
                .Concat(authenticatorData.RpIdHash)
                .Concat(clientDataHash)
                .Concat(authenticatorData.AttestedCredentialData.CredentialId)
                .Concat(new byte[] { 0x04 })
                .Concat(credentialParameters.Q.X!)
                .Concat(credentialParameters.Q.Y!)
                .ToArray();
            var sig = attestationKey.SignData(verificationData, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (corruptSignature)
            {
                sig[^1] ^= 0x01;
            }

            var method1KeyIdentifier = Rfc5280Method1KeyIdentifier(attCert);
            return new(new(sig, new[] { attCert.RawData }), authenticatorData, clientDataHash, attCert.RawData, method1KeyIdentifier);
        }
    }

    private sealed class TestFidoU2FVerifier : DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>
    {
        public TestFidoU2FVerifier(RecordingFidoMetadataSearchService metadata) : this(metadata, Now)
        {
        }

        public TestFidoU2FVerifier(RecordingFidoMetadataSearchService metadata, DateTimeOffset now)
            : this(metadata, now, new FakeLogger<DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>>())
        {
        }

        private TestFidoU2FVerifier(RecordingFidoMetadataSearchService metadata, DateTimeOffset now, FakeLogger<DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>> logger)
            : base(
                new FakeTimeProvider(now),
                new DefaultAsn1Deserializer(NullLogger<DefaultAsn1Deserializer>.Instance),
                metadata,
                logger)
        {
            FakeLogger = logger;
        }

        public FakeLogger<DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>> FakeLogger { get; }

        public async Task<Result<VerifiedAttestationStatement>> VerifyAsync(FidoU2FAttestation attestation)
        {
            await using var context = CreateContext();
            return await VerifyAsync(context, attestation.AttStmt, attestation.AuthenticatorData, attestation.ClientDataHash, CancellationToken.None);
        }

        public bool ComputeKeyIdentifier(X509Certificate2 certificate, out byte[]? keyIdentifier)
        {
            return TryComputeAttestationCertificateKeyIdentifier(certificate, out keyIdentifier);
        }

        public Result<byte[]?> GetSki(X509Certificate2 certificate)
        {
            return GetSubjectKeyIdentifierIfExists(certificate);
        }

        public bool IsValidKey(X509Certificate2 certificate, out ECParameters? parameters)
        {
            return IsValidPublicKeyParameters(certificate, out parameters);
        }
    }
}
