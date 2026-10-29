using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.AuthenticationCeremony.VerifyAssertion;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation.Constants;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Services.Static;

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

    // the largest authenticator data that is accepted, and the length of its base64url encoding
    private const int MaxAuthenticatorDataSize = 128 * 1024;
    private const int MaxAuthenticatorDataLength = 174763;

    // the largest client data that is accepted, and the length of its base64url encoding
    private const int MaxClientDataJsonSize = 512 * 1024;
    private const int MaxClientDataJsonLength = 699051;

    private DefaultAuthenticationResponseDecoder Decoder { get; set; } = null!;
    private FakeAuthenticationCeremonyCounters Counters { get; set; } = null!;
    private FakeLogger<DefaultAuthenticationResponseDecoder> Logger { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Counters = new();
        Logger = new();
        Decoder = new(
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>(),
            Counters,
            Logger);
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

    // The authenticator data is decoded before the signature over it is verified, so a response whose 'authenticatorData' encodes more than 128 KiB
    // is rejected before it is decoded. In an assertion the authenticator data takes 37 bytes plus the extension outputs.
    [Test]
    public void Decode_Succeeds_WhenAuthenticatorDataIsAtSizeLimit()
    {
        var authenticatorData = Base64Url.Encode(new byte[MaxAuthenticatorDataSize]);
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(ClientDataJson, authenticatorData, Signature), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(authenticatorData, Has.Length.EqualTo(MaxAuthenticatorDataLength));
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Response.AuthenticatorData, Has.Length.EqualTo(MaxAuthenticatorDataSize));
            Assert.That(Logger.Entries, Is.Empty);
            Assert.That(Counters.ResponseAnomalies, Is.Empty);
        });
    }

    [TestCase(MaxAuthenticatorDataSize + 1)]
    [TestCase(2 * MaxAuthenticatorDataSize)]
    public void Decode_Fails_AndLogsWarning_WhenAuthenticatorDataExceedsSizeLimit(int size)
    {
        var authenticatorData = Base64Url.Encode(new byte[size]);
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(ClientDataJson, authenticatorData, Signature), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { AuthenticatorDataTooLargeWarning(authenticatorData.Length) }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(AuthenticationResponseAnomalies.AuthenticatorDataTooLarge, false) }));
        });
    }

    // The client data is parsed as JSON before the signature over its hash is verified, so a response whose 'clientDataJSON' encodes more than 512 KiB
    // is rejected before it is decoded. A browser sends a few hundred bytes of client data.
    [Test]
    public void Decode_Succeeds_WhenClientDataJsonIsAtSizeLimit()
    {
        var clientDataJson = Base64Url.Encode(new byte[MaxClientDataJsonSize]);
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(clientDataJson, AuthenticatorData, Signature), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(clientDataJson, Has.Length.EqualTo(MaxClientDataJsonLength));
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Response.ClientDataJson, Has.Length.EqualTo(MaxClientDataJsonSize));
            Assert.That(Logger.Entries, Is.Empty);
            Assert.That(Counters.ResponseAnomalies, Is.Empty);
        });
    }

    [TestCase(MaxClientDataJsonSize + 1)]
    [TestCase(2 * MaxClientDataJsonSize)]
    public void Decode_Fails_AndLogsWarning_WhenClientDataJsonExceedsSizeLimit(int size)
    {
        var clientDataJson = Base64Url.Encode(new byte[size]);
        var response = CreateResponse(CredentialId, CredentialId, CreateAssertionResponse(clientDataJson, AuthenticatorData, Signature), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { ClientDataJsonTooLargeWarning(clientDataJson.Length) }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(AuthenticationResponseAnomalies.ClientDataJsonTooLarge, false) }));
        });
    }

    private IEnumerable<string> Warnings()
    {
        return Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message);
    }

    private static string AuthenticatorDataTooLargeWarning(int length)
    {
        return $"The 'response.authenticatorData' of the authentication response is {length.ToString(CultureInfo.InvariantCulture)} characters long, "
               + $"which exceeds the maximum of {MaxAuthenticatorDataLength.ToString(CultureInfo.InvariantCulture)} characters "
               + $"(the base64url encoding of {MaxAuthenticatorDataSize.ToString(CultureInfo.InvariantCulture)} bytes); the response is rejected";
    }

    private static string ClientDataJsonTooLargeWarning(int length)
    {
        return $"The 'response.clientDataJSON' of the authentication response is {length.ToString(CultureInfo.InvariantCulture)} characters long, "
               + $"which exceeds the maximum of {MaxClientDataJsonLength.ToString(CultureInfo.InvariantCulture)} characters "
               + $"(the base64url encoding of {MaxClientDataJsonSize.ToString(CultureInfo.InvariantCulture)} bytes); the response is rejected";
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
