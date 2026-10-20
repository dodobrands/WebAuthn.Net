using System.Collections.Generic;
using System.Text.Json;
using NUnit.Framework;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;

public class DefaultRegistrationResponseDecoderTests
{
    // base64url of the 16 bytes 0x00..0x0f
    private const string CredentialId = "AAECAwQFBgcICQoLDA0ODw";

    // base64url of "{}"
    private const string ClientDataJson = "e30";

    // base64url of the empty CBOR map (0xa0)
    private const string AttestationObject = "oA";

    private const string PublicKeyType = "public-key";

    private DefaultRegistrationResponseDecoder Decoder { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Decoder = new(
            new DefaultEnumMemberAttributeSerializer<AuthenticatorTransport>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>());
    }

    [Test]
    public void Decode_Succeeds_WhenAllRequiredMembersArePresent()
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(ClientDataJson, AttestationObject), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Id, Has.Length.EqualTo(16));
            Assert.That(result.Ok?.RawId, Is.EqualTo(result.Ok?.Id));
            Assert.That(result.Ok?.Type, Is.EqualTo(PublicKeyCredentialType.PublicKey));
            Assert.That(result.Ok?.Response.ClientDataJson, Is.EqualTo("{}"u8.ToArray()));
            Assert.That(result.Ok?.Response.AttestationObject, Is.EqualTo(new byte[] { 0xa0 }));
        });
    }

    // https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson - 'response' is a required member;
    // before the fix a null 'response' threw ArgumentNullException out of the decoder instead of being reported as a decoding failure
    [Test]
    public void Decode_Fails_WhenResponseIsNull()
    {
        var response = CreateResponse(CredentialId, CredentialId, null, PublicKeyType);

        Result<RegistrationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenIdIsNullOrEmpty(string? id)
    {
        var response = CreateResponse(id, CredentialId, CreateAttestationResponse(ClientDataJson, AttestationObject), PublicKeyType);

        Result<RegistrationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenRawIdIsNullOrEmpty(string? rawId)
    {
        var response = CreateResponse(CredentialId, rawId, CreateAttestationResponse(ClientDataJson, AttestationObject), PublicKeyType);

        Result<RegistrationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("public-key-2")]
    public void Decode_Fails_WhenTypeIsNullEmptyOrUnknown(string? type)
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(ClientDataJson, AttestationObject), type);

        Result<RegistrationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenClientDataJsonIsNullOrEmpty(string? clientDataJson)
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(clientDataJson, AttestationObject), PublicKeyType);

        Result<RegistrationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenAttestationObjectIsNullOrEmpty(string? attestationObject)
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(ClientDataJson, attestationObject), PublicKeyType);

        Result<RegistrationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [Test]
    public void Decode_Fails_WhenIdIsNotBase64Url()
    {
        var response = CreateResponse("not+base64/url=", CredentialId, CreateAttestationResponse(ClientDataJson, AttestationObject), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.That(result.HasError, Is.True);
    }

    private static RegistrationResponseJSON CreateResponse(
        string? id,
        string? rawId,
        AuthenticatorAttestationResponseJSON? response,
        string? type)
    {
        return new(
            id!,
            rawId!,
            response!,
            null,
            new Dictionary<string, JsonElement>(),
            type!);
    }

    private static AuthenticatorAttestationResponseJSON CreateAttestationResponse(string? clientDataJson, string? attestationObject)
    {
        return new(
            clientDataJson!,
            null,
            null,
            null,
            null,
            attestationObject!);
    }
}
