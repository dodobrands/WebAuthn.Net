using System.Collections.Generic;
using System.Text.Json;
using NUnit.Framework;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder.Implementation;

public class DefaultAuthenticationResponseDecoderTests
{
    // base64url of the 16 bytes 0x00..0x0f
    private const string CredentialId = "AAECAwQFBgcICQoLDA0ODw";

    // base64url of "{}"
    private const string ClientDataJson = "e30";

    // base64url of 32 bytes 0x11
    private const string AuthenticatorData = "ERERERERERERERERERERERERERERERERERERERERERE";

    // base64url of 0x01 0x02 0x03
    private const string Signature = "AQID";

    private const string PublicKeyType = "public-key";

    private DefaultAuthenticationResponseDecoder Decoder { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Decoder = new(
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>());
    }

    [Test]
    public void Decode_Succeeds_WhenAllRequiredMembersArePresent()
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(ClientDataJson, AuthenticatorData, Signature), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Id, Has.Length.EqualTo(16));
            Assert.That(result.Ok?.RawId, Is.EqualTo(result.Ok?.Id));
            Assert.That(result.Ok?.Type, Is.EqualTo(PublicKeyCredentialType.PublicKey));
            Assert.That(result.Ok?.Response.ClientDataJson, Is.EqualTo("{}"u8.ToArray()));
            Assert.That(result.Ok?.Response.AuthenticatorData, Has.Length.EqualTo(32));
            Assert.That(result.Ok?.Response.Signature, Is.EqualTo(new byte[] { 0x01, 0x02, 0x03 }));
            Assert.That(result.Ok?.Response.UserHandle, Is.Null);
        });
    }

    // https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson - 'id', 'rawId', 'response' and 'type' are required members
    [Test]
    public void Decode_Fails_WhenResponseIsNull()
    {
        var response = CreateResponse(CredentialId, CredentialId, null, PublicKeyType);

        Result<AuthenticationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenIdIsNullOrEmpty(string? id)
    {
        var response = CreateResponse(id, CredentialId, CreateAssertionResponse(ClientDataJson, AuthenticatorData, Signature), PublicKeyType);

        Result<AuthenticationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenRawIdIsNullOrEmpty(string? rawId)
    {
        var response = CreateResponse(CredentialId, rawId, CreateAssertionResponse(ClientDataJson, AuthenticatorData, Signature), PublicKeyType);

        Result<AuthenticationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("public-key-2")]
    public void Decode_Fails_WhenTypeIsNullEmptyOrUnknown(string? type)
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(ClientDataJson, AuthenticatorData, Signature), type);

        Result<AuthenticationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenClientDataJsonIsNullOrEmpty(string? clientDataJson)
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(clientDataJson, AuthenticatorData, Signature), PublicKeyType);

        Result<AuthenticationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenAuthenticatorDataIsNullOrEmpty(string? authenticatorData)
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(ClientDataJson, authenticatorData, Signature), PublicKeyType);

        Result<AuthenticationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    public void Decode_Fails_WhenSignatureIsNullOrEmpty(string? signature)
    {
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(ClientDataJson, AuthenticatorData, signature), PublicKeyType);

        Result<AuthenticationResponse>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(response));

        Assert.That(result?.HasError, Is.True);
    }

    private static AuthenticationResponseJSON CreateResponse(
        string? id,
        string? rawId,
        AuthenticatorAssertionResponseJSON? response,
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

    private static AuthenticatorAssertionResponseJSON CreateAssertionResponse(string? clientDataJson, string? authenticatorData, string? signature)
    {
        return new(
            clientDataJson!,
            authenticatorData!,
            signature!,
            null);
    }
}
