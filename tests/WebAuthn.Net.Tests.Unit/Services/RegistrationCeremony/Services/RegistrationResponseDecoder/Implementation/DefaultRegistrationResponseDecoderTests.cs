using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Models.Protocol.Json.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation.Constants;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Services.Static;

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

    // the largest attestation object that is accepted, and the length of its base64url encoding
    private const int MaxAttestationObjectSize = 512 * 1024;
    private const int MaxAttestationObjectLength = 699051;

    // the largest client data that is accepted, and the length of its base64url encoding
    private const int MaxClientDataJsonSize = 512 * 1024;
    private const int MaxClientDataJsonLength = 699051;

    private static readonly string[] EveryKnownTransport = { "hybrid", "internal", "usb", "nfc", "ble", "smart-card" };
    private static readonly string[] RepeatedTransports = { "usb", "nfc", "usb", "usb", "nfc" };
    private static readonly string[] RepeatedAndUnknownTransports = { "usb", "usb", "future-transport" };
    private static readonly string[] RepeatedUnknownTransport = { "future-transport", "future-transport", "future-transport" };

    private DefaultRegistrationResponseDecoder Decoder { get; set; } = null!;
    private FakeRegistrationCeremonyCounters Counters { get; set; } = null!;
    private FakeLogger<DefaultRegistrationResponseDecoder> Logger { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Counters = new();
        Logger = new();
        Decoder = new(
            new DefaultEnumMemberAttributeSerializer<AuthenticatorTransport>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>(),
            Counters,
            Logger);
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

    [Test]
    public void Decode_ReturnsNoTransports_WithoutWarnings_WhenResponseHasNoTransports()
    {
        var result = Decoder.Decode(CreateResponseWithTransports(null));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Response.Transports, Is.Null);
            Assert.That(Logger.Entries, Is.Empty);
            Assert.That(Counters.ResponseAnomalies, Is.Empty);
        });
    }

    [Test]
    public void Decode_ReturnsTransportsInTheirOrder_WithoutWarnings_WhenEveryTransportIsKnown()
    {
        var result = Decoder.Decode(CreateResponseWithTransports(EveryKnownTransport));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                result.Ok?.Response.Transports,
                Is.EqualTo(new[]
                {
                    AuthenticatorTransport.Hybrid,
                    AuthenticatorTransport.Internal,
                    AuthenticatorTransport.Usb,
                    AuthenticatorTransport.Nfc,
                    AuthenticatorTransport.Ble,
                    AuthenticatorTransport.SmartCard
                }));
            Assert.That(Logger.Entries, Is.Empty);
            Assert.That(Counters.ResponseAnomalies, Is.Empty);
        });
    }

    // https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot - "The values SHOULD be members of AuthenticatorTransport but Relying Parties SHOULD accept and store unknown values".
    // The library can store only the members of AuthenticatorTransport and doesn't modify the transports reported by the client
    // (https://www.w3.org/TR/webauthn-3/#abstract-opdef-credential-record-transports), so a response with an unknown value is rejected.
    [TestCase("future-transport")]
    [TestCase("cable")]
    [TestCase("USB")]
    [TestCase("smart card")]
    [TestCase("")]
    public void Decode_Fails_AndLogsWarning_WhenTransportIsUnknown(string unknownTransport)
    {
        var result = Decoder.Decode(CreateResponseWithTransports(new[] { "hybrid", unknownTransport, "internal" }));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { UnknownTransportsWarning(1, $"'{unknownTransport}'") }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.TransportsUnknownValue, false) }));
        });
    }

    [Test]
    public void Decode_Fails_AndDescribesNullElementAsNull_WhenTransportsContainNull()
    {
        var result = Decoder.Decode(CreateResponseWithTransports(new[] { "usb", null }));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { UnknownTransportsWarning(1, "null") }));
        });
    }

    // https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponse-transports-slot - the values are unique
    [Test]
    public void Decode_Fails_AndLogsWarning_WhenTransportsRepeat()
    {
        var result = Decoder.Decode(CreateResponseWithTransports(RepeatedTransports));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { DuplicateTransportsWarning(3) }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.TransportsDuplicateValue, false) }));
        });
    }

    // The unknown values are checked before the duplicates, and the response is rejected by the first check that fails
    [Test]
    public void Decode_Fails_AndReportsOnlyUnknownTransports_WhenTransportsAlsoRepeat()
    {
        var result = Decoder.Decode(CreateResponseWithTransports(RepeatedAndUnknownTransports));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { UnknownTransportsWarning(1, "'future-transport'") }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.TransportsUnknownValue, false) }));
        });
    }

    // A client reports each transport of the authenticator once, so a response with more than 100 transports is rejected before any of them is examined
    [TestCase(101)]
    [TestCase(10_000)]
    public void Decode_Fails_AndLogsWarning_WhenThereAreMoreThanOneHundredTransports(int count)
    {
        var result = Decoder.Decode(CreateResponseWithTransports(Enumerable.Repeat("future-transport", count).ToArray()));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { TooManyTransportsWarning(count) }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.TransportsTooManyValues, false) }));
        });
    }

    // The transports are chosen by the client: however many unknown values there are, they are reported with a single Warning that contains their number
    // and lists at most 8 distinct values, and the anomaly is counted once per response

    [Test]
    public void Decode_ListsRepeatedUnknownTransportOnce()
    {
        var result = Decoder.Decode(CreateResponseWithTransports(RepeatedUnknownTransport));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { UnknownTransportsWarning(3, "'future-transport'") }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.TransportsUnknownValue, false) }));
        });
    }

    [Test]
    public void Decode_ListsEveryUnknownTransportInOneWarning_WhenThereAreEightDistinctUnknownTransports()
    {
        var transports = Enumerable.Range(0, 8).Select(static x => "t" + x.ToString(CultureInfo.InvariantCulture)).ToArray();

        var result = Decoder.Decode(CreateResponseWithTransports(transports));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { UnknownTransportsWarning(8, "'t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7'") }));
        });
    }

    [TestCase(9)]
    [TestCase(100)]
    public void Decode_ListsEightUnknownTransportsInOneWarning_WhenThereAreMoreDistinctUnknownTransports(int count)
    {
        var transports = Enumerable.Range(0, count).Select(static x => "t" + x.ToString(CultureInfo.InvariantCulture)).ToArray();

        var result = Decoder.Decode(CreateResponseWithTransports(transports));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { UnknownTransportsWarning(count, "'t0', 't1', 't2', 't3', 't4', 't5', 't6', 't7', ...") }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.TransportsUnknownValue, false) }));
        });
    }

    // An unknown value is untrusted input: its control characters are replaced and it is truncated to 64 characters, so that it can neither forge log entries nor flood the log
    [Test]
    public void Decode_NeutralizesAndTruncatesUnknownTransport_InWarning()
    {
        var transport = "ble\r\n" + new string('\u001b', 100);

        var result = Decoder.Decode(CreateResponseWithTransports(new[] { transport }));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { UnknownTransportsWarning(1, $"'ble{new string('?', 61)}...'") }));
        });
    }

    // The attestation object is decoded from CBOR before anything in it is verified, so a response whose 'attestationObject' encodes more than 512 KiB
    // is rejected before it is decoded. The largest attestation objects, those with a certificate chain, take less than 10 KB.
    [Test]
    public void Decode_Succeeds_WhenAttestationObjectIsAtSizeLimit()
    {
        var attestationObject = Base64Url.Encode(new byte[MaxAttestationObjectSize]);
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(ClientDataJson, attestationObject), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(attestationObject, Has.Length.EqualTo(MaxAttestationObjectLength));
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Response.AttestationObject, Has.Length.EqualTo(MaxAttestationObjectSize));
            Assert.That(Logger.Entries, Is.Empty);
            Assert.That(Counters.ResponseAnomalies, Is.Empty);
        });
    }

    [TestCase(MaxAttestationObjectSize + 1)]
    [TestCase(2 * MaxAttestationObjectSize)]
    public void Decode_Fails_AndLogsWarning_WhenAttestationObjectExceedsSizeLimit(int size)
    {
        var attestationObject = Base64Url.Encode(new byte[size]);
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(ClientDataJson, attestationObject), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { AttestationObjectTooLargeWarning(attestationObject.Length) }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.AttestationObjectTooLarge, false) }));
        });
    }

    // The client data is parsed as JSON before anything in it is verified, and the credential record keeps it, so a response whose 'clientDataJSON' encodes more than 512 KiB
    // is rejected before it is decoded. A browser sends a few hundred bytes of client data.
    [Test]
    public void Decode_Succeeds_WhenClientDataJsonIsAtSizeLimit()
    {
        var clientDataJson = Base64Url.Encode(new byte[MaxClientDataJsonSize]);
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(clientDataJson, AttestationObject), PublicKeyType);

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
        var response = CreateResponse(CredentialId, CredentialId, CreateAttestationResponse(clientDataJson, AttestationObject), PublicKeyType);

        var result = Decoder.Decode(response);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Warnings(), Is.EqualTo(new[] { ClientDataJsonTooLargeWarning(clientDataJson.Length) }));
            Assert.That(Counters.ResponseAnomalies, Is.EqualTo(new[] { new FakeResponseAnomaly(RegistrationResponseAnomalies.ClientDataJsonTooLarge, false) }));
        });
    }

    private IEnumerable<string> Warnings()
    {
        return Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message);
    }

    private static string AttestationObjectTooLargeWarning(int length)
    {
        return $"The 'response.attestationObject' of the registration response is {length.ToString(CultureInfo.InvariantCulture)} characters long, "
               + $"which exceeds the maximum of {MaxAttestationObjectLength.ToString(CultureInfo.InvariantCulture)} characters "
               + $"(the base64url encoding of {MaxAttestationObjectSize.ToString(CultureInfo.InvariantCulture)} bytes); the response is rejected";
    }

    private static string ClientDataJsonTooLargeWarning(int length)
    {
        return $"The 'response.clientDataJSON' of the registration response is {length.ToString(CultureInfo.InvariantCulture)} characters long, "
               + $"which exceeds the maximum of {MaxClientDataJsonLength.ToString(CultureInfo.InvariantCulture)} characters "
               + $"(the base64url encoding of {MaxClientDataJsonSize.ToString(CultureInfo.InvariantCulture)} bytes); the response is rejected";
    }

    private static string TooManyTransportsWarning(int count)
    {
        return $"The 'transports' of the registration response contain {count.ToString(CultureInfo.InvariantCulture)} values, which exceeds the maximum of 100; the response is rejected";
    }

    private static string UnknownTransportsWarning(int count, string values)
    {
        return $"The 'transports' of the registration response contain {count.ToString(CultureInfo.InvariantCulture)} value(s) unknown to the library: {values}; the response is rejected";
    }

    private static string DuplicateTransportsWarning(int count)
    {
        return $"The 'transports' of the registration response contain {count.ToString(CultureInfo.InvariantCulture)} duplicate value(s); the response is rejected";
    }

    private static RegistrationResponseJSON CreateResponseWithTransports(string?[]? transports)
    {
        return CreateResponse(
            CredentialId,
            CredentialId,
            new(ClientDataJson, null, transports!, null, null, AttestationObject),
            PublicKeyType);
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
