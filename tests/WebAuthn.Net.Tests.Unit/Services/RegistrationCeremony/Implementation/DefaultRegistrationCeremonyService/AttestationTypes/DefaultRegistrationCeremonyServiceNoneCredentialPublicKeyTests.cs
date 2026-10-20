using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Configuration.Options.AttestationTypes;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.AttestationTypes;

// 'none' attestation statements built here instead of recorded from an authenticator, so that the credential public key can be encoded in any way
public class DefaultRegistrationCeremonyServiceNoneCredentialPublicKeyTests : AbstractRegistrationCeremonyServiceTests
{
    private const string RpId = "vanbukin-pc.local";
    private static readonly byte[] Challenge = TpmAttestationBuilder.Pattern(32, 1);
    private static readonly byte[] CredentialId = TpmAttestationBuilder.Pattern(16, 100);

    protected override IEnumerable<KeyValuePair<string, string?>>? GetConfiguration()
    {
        yield return new($"{nameof(WebAuthnOptions.AttestationTypes)}:{nameof(AttestationTypeOptions.None)}:{nameof(NoneAttestationTypeOptions.IsAcceptable)}", "true");
    }

    protected override Uri GetRelyingPartyAddress()
    {
        return new($"https://{RpId}", UriKind.Absolute);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_PerformsCeremonyWithoutErrorsForNone_WhenEc2CoordinatesHaveTheLengthOfTheFieldElement()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;

        var hasError = await CompleteCeremonyHasErrorAsync(Ec2CoseKey(point.X!, point.Y!));

        Assert.That(hasError, Is.False);
    }

    [Test]
    public async Task DefaultRegistrationCeremonyService_FailsCeremonyForNone_WhenEc2CoordinatesArePaddedWithLeadingZeroOctet()
    {
        // the same integers as the coordinates of a valid key, encoded in 33 bytes: whether a signature verifies with such a key depends on the platform, so it must not be registered
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;
        var paddedX = new byte[] { 0x00 }.Concat(point.X!).ToArray();
        var paddedY = new byte[] { 0x00 }.Concat(point.Y!).ToArray();

        var hasError = await CompleteCeremonyHasErrorAsync(Ec2CoseKey(paddedX, paddedY));

        Assert.That(hasError, Is.True);
    }

    private async Task<bool> CompleteCeremonyHasErrorAsync(byte[] credentialPublicKey)
    {
        var userId = WebEncoders.Base64UrlDecode("AAAAAAAAAAAAAAAAAAAAAQ");
        var beginResult = await RegistrationCeremonyService.BeginCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                null,
                null,
                "Test Host",
                new("testuser", userId, "Test User"),
                32,
                new[]
                {
                    CoseAlgorithm.ES256
                },
                60000,
                RegistrationCeremonyExcludeCredentials.AllExisting(),
                new(AuthenticatorAttachment.Platform, null, null, UserVerificationRequirement.Required),
                null,
                AttestationConveyancePreference.Direct,
                null,
                null),
            CancellationToken.None);

        RegistrationCeremonyStorage.ReplaceChallengeForRegistrationCeremonyOptions(beginResult.RegistrationCeremonyId, Challenge);

        var clientDataJson = Encoding.UTF8.GetBytes($$"""{"type":"webauthn.create","challenge":"{{WebEncoders.Base64UrlEncode(Challenge)}}","origin":"https://{{RpId}}"}""");
        var credentialId = WebEncoders.Base64UrlEncode(CredentialId);
        var completeResult = await RegistrationCeremonyService.CompleteCeremonyAsync(
            new DefaultHttpContext(new FeatureCollection()),
            new(
                beginResult.RegistrationCeremonyId,
                null,
                new(
                    credentialId,
                    credentialId,
                    new(
                        WebEncoders.Base64UrlEncode(clientDataJson),
                        null,
                        null,
                        null,
                        null,
                        WebEncoders.Base64UrlEncode(NoneAttestationObject(credentialPublicKey))
                    ),
                    null,
                    new(),
                    "public-key")),
            CancellationToken.None);
        return completeResult.HasError;
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-attestation - attestation object with the 'none' attestation statement format
    private static byte[] NoneAttestationObject(byte[] credentialPublicKey)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
        var rpIdHash = SHA256.HashData(Encoding.UTF8.GetBytes(RpId));
        var authenticatorData = new byte[32 + 1 + 4 + 16 + 2 + CredentialId.Length + credentialPublicKey.Length];
        var offset = 0;
        rpIdHash.CopyTo(authenticatorData, offset);
        offset += rpIdHash.Length;
        authenticatorData[offset] = 0x45; // UP | UV | AT
        offset += 1;
        offset += 4; // signCount = 0
        offset += 16; // aaguid = 00000000-0000-0000-0000-000000000000
        authenticatorData[offset] = (byte) (CredentialId.Length >> 8);
        authenticatorData[offset + 1] = (byte) CredentialId.Length;
        offset += 2;
        CredentialId.CopyTo(authenticatorData, offset);
        offset += CredentialId.Length;
        credentialPublicKey.CopyTo(authenticatorData, offset);

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString("none");
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(authenticatorData);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] Ec2CoseKey(byte[] x, byte[] y)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); // kty
        writer.WriteInt32(2); // EC2
        writer.WriteInt32(3); // alg
        writer.WriteInt32((int) CoseAlgorithm.ES256);
        writer.WriteInt32(-1); // crv
        writer.WriteInt32(1); // P-256
        writer.WriteInt32(-2); // x
        writer.WriteByteString(x);
        writer.WriteInt32(-3); // y
        writer.WriteByteString(y);
        writer.WriteEndMap();
        return writer.Encode();
    }
}
