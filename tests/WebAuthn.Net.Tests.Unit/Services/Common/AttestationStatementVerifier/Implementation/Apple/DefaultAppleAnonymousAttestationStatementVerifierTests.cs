using System;
using System.Formats.Asn1;
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
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Apple.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using static WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AttestationStatementVerifierTestHelpers;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Apple;

// Tests of DefaultAppleAnonymousAttestationStatementVerifier.VerifyAsync: the attestation is built from scratch (a test CA issues credCert with the nonce extension),
// valid in every respect except the one rule a test breaks. The verifier does not validate the chain (that is the trust path validator's job), so the test CA stands in for Apple's.
public class DefaultAppleAnonymousAttestationStatementVerifierTests
{
    private const string NonceOid = "1.2.840.113635.100.8.2";

    // ---------------------------------------------------------------------------------------------
    // Positive

    [Test]
    public async Task VerifyAsync_Succeeds_WhenNonceAndCredentialPublicKeyMatch()
    {
        var verifier = new TestAppleVerifier();
        var attestation = AppleAttestation.Create(nonceExtensionValue: null);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.AppleAnonymous));
            Assert.That(result.Ok.AttestationType, Is.EqualTo(AttestationType.AnonCa));
            Assert.That(result.Ok.AttestationTrustPath, Is.EqualTo(attestation.AttStmt.X5C));
            Assert.That(result.Ok.AttestationRootCertificates, Is.EquivalentTo(AppleRoots.Certificates));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Step 4: the nonce extension (SEQUENCE { [1] EXPLICIT OCTET STRING (32 bytes) }) is client-supplied and must never throw

    [TestCase(new byte[] { 0x30, 0x00 }, TestName = "VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed(empty SEQUENCE)")]
    [TestCase(new byte[] { 0x30, 0x03, 0x81, 0x01, 0x00 }, TestName = "VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed([1] is primitive)")]
    [TestCase(new byte[] { 0x30, 0x08, 0xA1, 0x06, 0x04, 0x01, 0x02, 0x04, 0x01, 0x01 }, TestName = "VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed([1] has two OCTET STRINGs)")]
    [TestCase(new byte[] { 0x04, 0x00 }, TestName = "VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed(OCTET STRING instead of SEQUENCE)")]
    [TestCase(new byte[] { 0x30, 0x04, 0xA1, 0x02, 0x04, 0x00, 0x05, 0x00 }, TestName = "VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed(trailing data after SEQUENCE)")]
    [TestCase(new byte[] { 0x30, 0x04, 0xA0, 0x02, 0x04, 0x00 }, TestName = "VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed([0] instead of [1])")]
    [TestCase(new byte[] { 0x30, 0x05, 0xA1, 0x03, 0x02, 0x01, 0x00 }, TestName = "VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed(INTEGER instead of OCTET STRING)")]
    public async Task VerifyAsync_Fails_WithoutException_WhenNonceExtensionIsMalformed(byte[] extensionValue)
    {
        var verifier = new TestAppleVerifier();
        var attestation = AppleAttestation.Create(extensionValue);

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation));

        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            AssertWarning(verifier, "nonce extension (OID 1.2.840.113635.100.8.2) of the credCert of the Apple Anonymous attestation statement is malformed");
        });
    }

    [TestCase(31)]
    [TestCase(33)]
    [TestCase(0)]
    public async Task VerifyAsync_Fails_WhenNonceIsNotThirtyTwoBytes(int nonceLength)
    {
        var verifier = new TestAppleVerifier();
        var attestation = AppleAttestation.Create(AppleAttestation.NonceExtensionValue(new byte[nonceLength]));

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"is {nonceLength} byte(s) long, but a SHA-256 hash (32 bytes) is expected");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenNonceDoesNotMatchAuthenticatorDataAndClientDataHash()
    {
        var verifier = new TestAppleVerifier();
        var wrongNonce = new byte[32];
        wrongNonce[0] = 0xFF;
        var attestation = AppleAttestation.Create(AppleAttestation.NonceExtensionValue(wrongNonce));

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not equal to SHA-256(authenticatorData || clientDataHash)");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenNonceExtensionIsAbsent()
    {
        var verifier = new TestAppleVerifier();
        var attestation = AppleAttestation.Create(nonceExtensionValue: null, includeNonceExtension: false);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "does not contain the nonce extension");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Step 5: the credential public key must be the subject public key of credCert

    [Test]
    public async Task VerifyAsync_Fails_WhenCredentialPublicKeyDiffersFromCredCert()
    {
        var verifier = new TestAppleVerifier();
        var attestation = AppleAttestation.Create(nonceExtensionValue: null, mismatchedCredentialKey: true);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "credential public key is not equal to the Subject Public Key of the credCert");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // x5c

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CHasOnlyOneCertificate()
    {
        var verifier = new TestAppleVerifier();
        var attestation = AppleAttestation.Create(nonceExtensionValue: null);
        var singleCertificate = new AppleAnonymousAttestationStatement(new[] { attestation.AttStmt.X5C[0] });

        var result = await verifier.VerifyAsync(attestation with { AttStmt = singleCertificate });

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "contains 1 certificate(s), but at least 2");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CCertificateCannotBeLoaded()
    {
        var verifier = new TestAppleVerifier();
        var attestation = AppleAttestation.Create(nonceExtensionValue: null);
        var garbage = new AppleAnonymousAttestationStatement(new[] { new byte[] { 0x30, 0x03, 0x02, 0x01, 0x01 }, attestation.AttStmt.X5C[1] });

        var result = await verifier.VerifyAsync(attestation with { AttStmt = garbage });

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "Failed to load a certificate from the 'x5c'");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenX5CCertificateIsExpired()
    {
        var verifier = new TestAppleVerifier(Now.AddYears(2));
        var attestation = AppleAttestation.Create(nonceExtensionValue: null);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is not valid at the current time");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static void AssertWarning(TestAppleVerifier verifier, string messagePart)
    {
        Assert.That(
            verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
            Has.Some.Contains(messagePart),
            $"expected a Warning containing '{messagePart}'");
    }

    private sealed record AppleAttestation(AppleAnonymousAttestationStatement AttStmt, AttestedAuthenticatorData AuthenticatorData, byte[] ClientDataHash)
    {
        // SEQUENCE { [1] EXPLICIT OCTET STRING nonce }
        public static byte[] NonceExtensionValue(byte[] nonce)
        {
            var writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence())
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1)))
                {
                    writer.WriteOctetString(nonce);
                }
            }

            return writer.Encode();
        }

        // 'nonceExtensionValue' = null: the correct nonce (SHA-256 of authenticatorData || clientDataHash) is encoded; otherwise the given bytes are used verbatim as the extension value
        public static AppleAttestation Create(byte[]? nonceExtensionValue, bool includeNonceExtension = true, bool mismatchedCredentialKey = false)
        {
            using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var ca = CreateSelfSigned("CN=WebAuthn.Net Test Apple CA", caKey, true);
            using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var coseKey = ToCoseEc2Key(mismatchedCredentialKey ? otherKey : credentialKey);
            var authenticatorData = CreateAuthenticatorData(Guid.Empty, coseKey);
            var clientDataHash = CreateClientDataHash();
            var nonce = SHA256.HashData(Concat(authenticatorData.Raw, clientDataHash));
            var extensions = includeNonceExtension
                ? new X509Extension[] { new(NonceOid, nonceExtensionValue ?? NonceExtensionValue(nonce), false) }
                : Array.Empty<X509Extension>();
            using var credCert = Issue(ca, "CN=WebAuthn.Net Test Apple credCert", credentialKey, extensions);
            var attStmt = new AppleAnonymousAttestationStatement(new[] { credCert.RawData, ca.RawData });
            return new(attStmt, authenticatorData, clientDataHash);
        }
    }

    private sealed class TestAppleVerifier : DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>
    {
        public TestAppleVerifier() : this(Now)
        {
        }

        public TestAppleVerifier(DateTimeOffset now) : this(new FakeLogger<DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>>(), now)
        {
        }

        private TestAppleVerifier(FakeLogger<DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>> logger, DateTimeOffset now)
            : base(new FakeTimeProvider(now), new DefaultAsn1Deserializer(NullLogger<DefaultAsn1Deserializer>.Instance), logger)
        {
            FakeLogger = logger;
        }

        public FakeLogger<DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>> FakeLogger { get; }

        public async Task<Result<VerifiedAttestationStatement>> VerifyAsync(AppleAttestation attestation)
        {
            await using var context = CreateContext();
            return await VerifyAsync(context, attestation.AttStmt, attestation.AuthenticatorData, attestation.ClientDataHash, CancellationToken.None);
        }
    }
}
