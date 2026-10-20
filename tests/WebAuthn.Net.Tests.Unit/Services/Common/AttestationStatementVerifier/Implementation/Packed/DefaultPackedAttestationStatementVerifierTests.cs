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
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;
using WebAuthn.Net.Services.Static;
using static WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AttestationStatementVerifierTestHelpers;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed;

// Tests of DefaultPackedAttestationStatementVerifier.VerifyAsync: every attestation is built from scratch (a test root issues attestnCert, the FIDO Metadata Service stand-in knows the AAGUID),
// valid in every respect except the one rule a test breaks, so a test fails only if the check it names is missing.
public class DefaultPackedAttestationStatementVerifierTests
{
    private const string AttestationSubject = "C=SE, O=WebAuthn.Net, OU=Authenticator Attestation, CN=WebAuthn.Net Test Attestation";

    // ---------------------------------------------------------------------------------------------
    // Positive

    [Test]
    public async Task VerifyAsync_Succeeds_ForX5CAttestation_WhenMetadataListsBasicFull()
    {
        var attestation = PackedAttestation.Create();
        var verifier = new TestPackedVerifier(attestation.Metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.Packed));
            Assert.That(result.Ok.AttestationType, Is.EqualTo(AttestationType.Basic));
            Assert.That(result.Ok.AttestationTrustPath, Is.EqualTo(attestation.AttStmt.X5C));
            Assert.That(result.Ok.AttestationRootCertificates, Is.EquivalentTo(new[] { attestation.Root }));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_ForSelfAttestation()
    {
        var attestation = PackedAttestation.CreateSelf();
        var verifier = new TestPackedVerifier(attestation.Metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationType, Is.EqualTo(AttestationType.Self));
            Assert.That(result.Ok.AttestationTrustPath, Is.Null);
            Assert.That(result.Ok.AttestationRootCertificates, Is.Null);
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Certificate requirements: the typed Basic Constraints extension is decoded lazily and is client-supplied, so a malformed value must fail, not throw

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenBasicConstraintsExtensionIsMalformed()
    {
        // NULL instead of SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
        var attestation = PackedAttestation.Create(basicConstraints: new X509Extension("2.5.29.19", new byte[] { 0x05, 0x00 }, true), writeAttestnCertDirectly: true);
        var verifier = new TestPackedVerifier(attestation.Metadata);

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation));

        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            Assert.That(verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning), Is.Not.Empty);
        });
    }

    [Test]
    public void IsBasicExtensionsCaComponentFalse_ReturnsFalse_WithoutException_WhenExtensionValueIsMalformed()
    {
        // the local guard of the verifier, independent of the certificate loader rejecting such certificates
        var attestation = PackedAttestation.Create(basicConstraints: new X509Extension("2.5.29.19", new byte[] { 0x05, 0x00 }, true), writeAttestnCertDirectly: true);
        var verifier = new TestPackedVerifier(attestation.Metadata);
        using var certificate = LoadWithPlatformLoader(attestation.AttStmt.X5C![0]);
        if (certificate is null)
        {
            Assert.Ignore("the platform refuses to load a certificate with a malformed Basic Constraints extension");
            return;
        }

        var isCaComponentFalse = true;
        Assert.DoesNotThrow(() => isCaComponentFalse = verifier.IsBasicConstraintsCaFalse(certificate));

        Assert.Multiple(() =>
        {
            Assert.That(isCaComponentFalse, Is.False);
            AssertWarning(verifier, "Basic Constraints extension of the attestnCert of the Packed attestation statement is malformed");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenBasicConstraintsCaIsTrue()
    {
        var attestation = PackedAttestation.Create(basicConstraints: new X509BasicConstraintsExtension(true, false, 0, true));
        var verifier = new TestPackedVerifier(attestation.Metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "does not meet the Packed Attestation Statement Certificate Requirements: basic constraints");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenSubjectLacksAuthenticatorAttestationOrganizationalUnit()
    {
        var attestation = PackedAttestation.Create(subject: "C=SE, O=WebAuthn.Net, OU=Something Else, CN=WebAuthn.Net Test Attestation");
        var verifier = new TestPackedVerifier(attestation.Metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "does not meet the Packed Attestation Statement Certificate Requirements: subject");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Signature, aaguid, metadata

    [Test]
    public async Task VerifyAsync_Fails_WhenSignatureIsInvalid()
    {
        var attestation = PackedAttestation.Create(corruptSignature: true);
        var verifier = new TestPackedVerifier(attestation.Metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'sig' of the Packed attestation statement is not a valid signature");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenAaguidExtensionDoesNotMatchAuthenticatorData()
    {
        var attestation = PackedAttestation.Create(aaguidExtension: Guid.Parse("00000000-0000-0000-0000-00000000beef"));
        var verifier = new TestPackedVerifier(attestation.Metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "id-fido-gen-ce-aaguid extension of the attestnCert of the Packed attestation statement does not match");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenMetadataIsNotFound()
    {
        var attestation = PackedAttestation.Create();
        var verifier = new TestPackedVerifier(new RecordingFidoMetadataSearchService());

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"no trusted metadata for the aaguid {Aaguid}");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // x5c

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CIsEmpty()
    {
        var attestation = PackedAttestation.Create();
        var verifier = new TestPackedVerifier(attestation.Metadata);
        var emptyX5C = new PackedAttestationStatement(attestation.AttStmt.Alg, attestation.AttStmt.Sig, Array.Empty<byte[]>());

        var result = await verifier.VerifyAsync(attestation with { AttStmt = emptyX5C });

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'x5c' of the Packed attestation statement is present but empty");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CContainsSelfSignedCertificate()
    {
        var attestation = PackedAttestation.Create();
        var verifier = new TestPackedVerifier(attestation.Metadata);
        var withRoot = new PackedAttestationStatement(attestation.AttStmt.Alg, attestation.AttStmt.Sig, new[] { attestation.AttStmt.X5C![0], attestation.Root });

        var result = await verifier.VerifyAsync(attestation with { AttStmt = withRoot });

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "contains a self-signed (root) certificate");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CCertificateIsExpired()
    {
        var attestation = PackedAttestation.Create();
        var verifier = new TestPackedVerifier(attestation.Metadata, Now.AddYears(2));

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not valid at the current time");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Self attestation

    [Test]
    public async Task VerifyAsync_Fails_ForSelfAttestation_WhenAlgDoesNotMatchCredentialPublicKey()
    {
        var attestation = PackedAttestation.CreateSelf();
        var verifier = new TestPackedVerifier(attestation.Metadata);
        var wrongAlg = new PackedAttestationStatement(CoseAlgorithm.ES384, attestation.AttStmt.Sig, null);

        var result = await verifier.VerifyAsync(attestation with { AttStmt = wrongAlg });

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "of the Packed self attestation statement does not match the algorithm");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_ForSelfAttestation_WhenSignatureIsInvalid()
    {
        var attestation = PackedAttestation.CreateSelf(corruptSignature: true);
        var verifier = new TestPackedVerifier(attestation.Metadata);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'sig' of the Packed self attestation statement is not a valid signature");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static void AssertWarning(TestPackedVerifier verifier, string messagePart)
    {
        Assert.That(
            verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
            Has.Some.Contains(messagePart),
            $"expected a Warning containing '{messagePart}'");
    }

    private sealed record PackedAttestation(PackedAttestationStatement AttStmt, AttestedAuthenticatorData AuthenticatorData, byte[] ClientDataHash, byte[] Root, RecordingFidoMetadataSearchService Metadata)
    {
        // 'writeAttestnCertDirectly': the attestnCert is written as DER without being loaded by the platform (CertificateRequest.Create loads the certificate it creates, and macOS refuses malformed extensions)
        public static PackedAttestation Create(
            X509Extension? basicConstraints = null,
            string subject = AttestationSubject,
            bool corruptSignature = false,
            Guid? aaguidExtension = null,
            bool writeAttestnCertDirectly = false)
        {
            using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var root = CreateSelfSigned("CN=WebAuthn.Net Test Attestation Root", rootKey, true);
            using var attestationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var extensions = new System.Collections.Generic.List<X509Extension> { basicConstraints ?? EndEntityBasicConstraints() };
            if (aaguidExtension.HasValue)
            {
                // id-fido-gen-ce-aaguid: OCTET STRING (16 bytes) inside the extnValue OCTET STRING
                extensions.Add(new X509Extension("1.3.6.1.4.1.45724.1.1.4", new byte[] { 0x04, 0x10 }.Concat(aaguidExtension.Value.ToByteArray(true)).ToArray(), false));
            }

            byte[] attestnCertBytes;
            if (writeAttestnCertDirectly)
            {
                attestnCertBytes = BuildCertificate(rootKey, "CN=WebAuthn.Net Test Attestation Root", subject, attestationKey.ExportSubjectPublicKeyInfo(), extensions);
            }
            else
            {
                using var attestnCert = Issue(root, subject, attestationKey, extensions.ToArray());
                attestnCertBytes = attestnCert.RawData;
            }

            using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var authenticatorData = CreateAuthenticatorData(Aaguid, ToCoseEc2Key(credentialKey));
            var clientDataHash = CreateClientDataHash();
            var sig = attestationKey.SignData(Concat(authenticatorData.Raw, clientDataHash), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (corruptSignature)
            {
                sig[^1] ^= 0x01;
            }

            var metadata = new RecordingFidoMetadataSearchService().WithAaguid(Aaguid, RecordingFidoMetadataSearchService.Metadata(root, AuthenticatorAttestationType.ATTESTATION_BASIC_FULL));
            return new(new(CoseAlgorithm.ES256, sig, new[] { attestnCertBytes }), authenticatorData, clientDataHash, root.RawData, metadata);
        }

        public static PackedAttestation CreateSelf(bool corruptSignature = false)
        {
            using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var authenticatorData = CreateAuthenticatorData(Aaguid, ToCoseEc2Key(credentialKey));
            var clientDataHash = CreateClientDataHash();
            var sig = credentialKey.SignData(Concat(authenticatorData.Raw, clientDataHash), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
            if (corruptSignature)
            {
                sig[^1] ^= 0x01;
            }

            return new(new(CoseAlgorithm.ES256, sig, null), authenticatorData, clientDataHash, Array.Empty<byte>(), new RecordingFidoMetadataSearchService());
        }
    }

    private sealed class TestPackedVerifier : DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>
    {
        public TestPackedVerifier(RecordingFidoMetadataSearchService metadata) : this(metadata, Now)
        {
        }

        public TestPackedVerifier(RecordingFidoMetadataSearchService metadata, DateTimeOffset now)
            : this(metadata, now, new FakeLogger<DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>>())
        {
        }

        private TestPackedVerifier(RecordingFidoMetadataSearchService metadata, DateTimeOffset now, FakeLogger<DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>> logger)
            : base(
                new FakeTimeProvider(now),
                new DefaultDigitalSignatureVerifier(),
                new DefaultAsn1Deserializer(NullLogger<DefaultAsn1Deserializer>.Instance),
                metadata,
                logger)
        {
            FakeLogger = logger;
        }

        public FakeLogger<DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>> FakeLogger { get; }

        public async Task<Result<VerifiedAttestationStatement>> VerifyAsync(PackedAttestation attestation)
        {
            await using var context = CreateContext();
            return await VerifyAsync(context, attestation.AttStmt, attestation.AuthenticatorData, attestation.ClientDataHash, CancellationToken.None);
        }

        public bool IsBasicConstraintsCaFalse(X509Certificate2 certificate)
        {
            return IsBasicExtensionsCaComponentFalse(certificate);
        }
    }
}
