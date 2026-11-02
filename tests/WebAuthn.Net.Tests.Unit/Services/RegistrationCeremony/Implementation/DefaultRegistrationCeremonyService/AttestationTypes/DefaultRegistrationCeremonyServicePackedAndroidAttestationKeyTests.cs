using System;
using System.Formats.Cbor;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.AttestationTypes;

// An Android attestation key whose certificate is a CA, as in the chains of real devices, can sign any certificate: here, the attestation certificate of a "packed" attestation statement
// with the aaguid of the Android Authenticator, whose entry lists the root certificates of the key attestation of Google. Nobody outside Google can issue a certificate under them,
// so the chain ends at the root certificate of a test hierarchy, which the entry lists as well and which the trust path validation takes for a root certificate of the key attestation of Google.
public class DefaultRegistrationCeremonyServicePackedAndroidAttestationKeyTests : AbstractRegistrationCeremonyServiceTests
{
    private const string RpId = "example.com";

    protected override Uri GetRelyingPartyAddress()
    {
        return new($"https://{RpId}", UriKind.Absolute);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremonyForPacked_WhenAttestationKeyOfChainToGoogleRootIsInStatusList()
    {
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        await TrustAsGoogleRootAsync(hierarchy.Root);
        AndroidKeyStatusStorage.StatusList = FakeAndroidKeyAttestationStatusStorage.With(AndroidAttestationKeyHierarchy.AttestationKeySerialNumber);

        var completeResult = await CompleteCeremonyAsync(hierarchy);

        Assert.Multiple(() =>
        {
            Assert.That(completeResult.HasError, Is.True);
            Assert.That(AndroidKeyStatusCounters.CertificatesListed, Is.EqualTo(1));
            Assert.That(
                AttestationTrustPathValidatorLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).EqualTo($"The certificate #1 (serial number '{AndroidAttestationKeyHierarchy.AttestationKeySerialNumber}') of the certificate chain of the 'Packed' attestation statement is in the certificate revocation status list of the Android attestation keys with the status 'Revoked' and the reason 'KeyCompromise'"));
        });
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremonyForPacked_WhenChainEndsAtGoogleRootAndNoStatusListIsAvailable()
    {
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        await TrustAsGoogleRootAsync(hierarchy.Root);
        AndroidKeyStatusStorage.StatusList = null;

        var completeResult = await CompleteCeremonyAsync(hierarchy);

        Assert.Multiple(() =>
        {
            Assert.That(completeResult.HasError, Is.True);
            Assert.That(AndroidKeyStatusCounters.ChecksWithoutStatusList, Is.EqualTo(1));
            Assert.That(
                AttestationTrustPathValidatorLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).EqualTo("The certificate revocation status list of the Android attestation keys is not available, so the 'Packed' attestation statement, whose certificate chain ends at a root certificate of the key attestation of Google, is rejected"));
        });
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyForPacked_WhenNoCertificateOfChainToGoogleRootIsInStatusList()
    {
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        await TrustAsGoogleRootAsync(hierarchy.Root);
        AndroidKeyStatusStorage.StatusList = FakeAndroidKeyAttestationStatusStorage.With("1228286566665971148");

        var completeResult = await CompleteCeremonyAsync(hierarchy);

        Assert.Multiple(() =>
        {
            Assert.That(completeResult.HasError, Is.False);
            Assert.That(AndroidKeyStatusCounters.CertificatesListed, Is.Zero);
            Assert.That(AttestationTrustPathValidatorLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyForPacked_WhenChainEndsAtOtherRootAndNoStatusListIsAvailable()
    {
        // the root certificate of the test hierarchy is listed by the entry, but it is not taken for a root certificate of the key attestation of Google:
        // the attestation statements of other authenticators don't depend on the status list of the Android attestation keys
        using var hierarchy = new AndroidAttestationKeyHierarchy();
        await UpsertAndroidAuthenticatorEntryWithRootAsync(hierarchy.Root);
        AndroidKeyStatusStorage.StatusList = null;

        var completeResult = await CompleteCeremonyAsync(hierarchy);

        Assert.Multiple(() =>
        {
            Assert.That(completeResult.HasError, Is.False);
            Assert.That(AndroidKeyStatusCounters.ChecksWithoutStatusList, Is.Zero);
            Assert.That(AttestationTrustPathValidatorLogger.Entries, Is.Empty);
        });
    }

    private async Task TrustAsGoogleRootAsync(byte[] root)
    {
        AttestationTrustPathValidator.GoogleRoots.Add(root);
        await UpsertAndroidAuthenticatorEntryWithRootAsync(root);
    }

    // the entry of the Android Authenticator lists its root certificates and the root certificate of the test hierarchy
    private async Task UpsertAndroidAuthenticatorEntryWithRootAsync(byte[] root)
    {
        var aaguid = MetadataBlobPayloadEdits.AndroidAuthenticatorAaguid;
        var entry = MetadataBlob.Entries.Single(x => x.Aaguid == aaguid);
        var roots = entry.MetadataStatement!.AttestationRootCertificates.Append(root).ToArray();
        await MetadataStorage.UpsertAsync(MetadataBlob.WithEntryCopy(aaguid, aaguid, null, roots), CancellationToken.None);
    }

    private async Task<Result<CompleteRegistrationCeremonyResult>> CompleteCeremonyAsync(AndroidAttestationKeyHierarchy hierarchy)
    {
        var userId = RandomNumberGenerator.GetBytes(16);
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                null,
                null,
                "Test Host",
                new("testuser", userId, "Test User"),
                32,
                new[] { CoseAlgorithm.ES256 },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(AuthenticatorAttachment.Platform, null, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);
        var challenge = RandomNumberGenerator.GetBytes(32);
        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(beginResult.RegistrationCeremonyId, challenge);

        var clientDataJson = Encoding.UTF8.GetBytes($"{{\"type\":\"webauthn.create\",\"challenge\":\"{WebEncoders.Base64UrlEncode(challenge)}\",\"origin\":\"https://{RpId}\",\"crossOrigin\":false}}");
        var credentialId = RandomNumberGenerator.GetBytes(32);
        using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var authenticatorData = CreateAuthenticatorData(MetadataBlobPayloadEdits.AndroidAuthenticatorAaguid, credentialId, credentialKey);
        // full "packed" attestation: the attestation certificate is signed with the attestation key of the hierarchy
        using var attestationCertificateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var attestationCertificate = hierarchy.IssuePackedAttestationCertificate(attestationCertificateKey);
        var signature = attestationCertificateKey.SignData(
            authenticatorData.Concat(SHA256.HashData(clientDataJson)).ToArray(),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        var attestationObject = CreatePackedAttestationObject(
            signature,
            new[] { attestationCertificate, hierarchy.AttestationKeyCertificate, hierarchy.Intermediate },
            authenticatorData);

        var id = WebEncoders.Base64UrlEncode(credentialId);
        return await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    id,
                    id,
                    new(
                        WebEncoders.Base64UrlEncode(clientDataJson),
                        null,
                        null,
                        null,
                        null,
                        WebEncoders.Base64UrlEncode(attestationObject)),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
    }

    private static byte[] CreateAuthenticatorData(Guid aaguid, byte[] credentialId, ECDsa credentialKey)
    {
        var parameters = credentialKey.ExportParameters(false);
        var credentialPublicKey = new CborWriter(CborConformanceMode.Ctap2Canonical);
        credentialPublicKey.WriteStartMap(5);
        credentialPublicKey.WriteInt32(1); // kty: EC2
        credentialPublicKey.WriteInt32(2);
        credentialPublicKey.WriteInt32(3); // alg: ES256
        credentialPublicKey.WriteInt32(-7);
        credentialPublicKey.WriteInt32(-1); // crv: P-256
        credentialPublicKey.WriteInt32(1);
        credentialPublicKey.WriteInt32(-2);
        credentialPublicKey.WriteByteString(parameters.Q.X!);
        credentialPublicKey.WriteInt32(-3);
        credentialPublicKey.WriteByteString(parameters.Q.Y!);
        credentialPublicKey.WriteEndMap();
        using var stream = new MemoryStream();
        stream.Write(SHA256.HashData(Encoding.UTF8.GetBytes(RpId)));
        stream.WriteByte(0x45); // UP, UV, AT
        stream.Write(new byte[4]);
        stream.Write(aaguid.ToByteArray(true));
        stream.WriteByte((byte) (credentialId.Length >> 8));
        stream.WriteByte((byte) credentialId.Length);
        stream.Write(credentialId);
        stream.Write(credentialPublicKey.Encode());
        return stream.ToArray();
    }

    private static byte[] CreatePackedAttestationObject(byte[] signature, byte[][] x5C, byte[] authenticatorData)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString("packed");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(3);
        writer.WriteTextString("alg");
        writer.WriteInt32(-7);
        writer.WriteTextString("sig");
        writer.WriteByteString(signature);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(x5C.Length);
        foreach (var certificate in x5C)
        {
            writer.WriteByteString(certificate);
        }

        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authenticatorData);
        writer.WriteEndMap();
        return writer.Encode();
    }
}
