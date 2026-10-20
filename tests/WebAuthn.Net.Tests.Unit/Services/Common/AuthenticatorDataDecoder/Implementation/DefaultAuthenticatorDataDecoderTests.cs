using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Abstractions;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Implementation;

namespace WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;

public class DefaultAuthenticatorDataDecoderTests
{
    private static readonly byte[] RpIdHash = SHA256.HashData("example.com"u8);
    private static readonly byte[] Aaguid = Guid.Parse("08987058-cadc-4b81-b6e1-30de50dcbe96").ToByteArray(true);
    private static readonly byte[] SignCount = { 0x00, 0x00, 0x00, 0x01 };
    private static readonly byte[] CoseKey = CreateEs256CoseKey();

    private FakeLogger<DefaultAuthenticatorDataDecoder> Logger { get; set; } = null!;

    private DefaultAuthenticatorDataDecoder Decoder { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Logger = new();
        var cborDeserializer = new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance);
        var coseKeyDeserializer = new DefaultCoseKeyDeserializer(cborDeserializer, NullLogger<DefaultCoseKeyDeserializer>.Instance);
        Decoder = new(coseKeyDeserializer, cborDeserializer, Logger);
    }

    [TestCase(16)]
    [TestCase(17)]
    [TestCase(1023)]
    public void Decode_Succeeds_WhenCredentialIdLengthIsWithinLimits(int credentialIdLength)
    {
        var authData = BuildAuthData(
            AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData,
            BuildAttestedCredentialData(credentialIdLength),
            null);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok, Is.InstanceOf<AttestedAuthenticatorData>());
            Assert.That(((AttestedAuthenticatorData) result.Ok!).AttestedCredentialData.CredentialId, Has.Length.EqualTo(credentialIdLength));
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    // WebAuthn Level 3 §4 Credential ID: "At least 16 bytes that include at least 100 bits of entropy".
    // Before the fix, the AttestedCredentialData constructor threw ArgumentException for these lengths and the exception escaped the decoder (and both ceremonies)
    // instead of being reported as a decoding failure.
    [TestCase(0)]
    [TestCase(1)]
    [TestCase(15)]
    public void Decode_Fails_WhenCredentialIdLengthIsLessThan16(int credentialIdLength)
    {
        var authData = BuildAuthData(
            AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData,
            BuildAttestedCredentialData(credentialIdLength),
            null);

        Result<AbstractAuthenticatorData>? result = null;
        Assert.DoesNotThrow(() => result = Decoder.Decode(authData));

        Assert.Multiple(() =>
        {
            Assert.That(result?.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo($"'attestedCredentialData.credentialIdLength' is {credentialIdLength}, which is less than the minimum limit of 16"));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Failed to read 'attestedCredentialData'"));
        });
    }

    [Test]
    public void Decode_Fails_WhenCredentialIdLengthIsGreaterThan1023()
    {
        var authData = BuildAuthData(
            AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData,
            BuildAttestedCredentialData(1024),
            null);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("'attestedCredentialData.credentialIdLength' is 1024, which is greater than the maximum limit of 1023"));
        });
    }

    [Test]
    public void Decode_Succeeds_WhenExtensionsIsCborMap()
    {
        // {"credProtect": 2}
        var extensions = Cbor(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("credProtect");
            writer.WriteInt32(2);
            writer.WriteEndMap();
        });
        var authData = BuildAuthData(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionDataIncluded, null, extensions);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok, Is.InstanceOf<NotAttestedAuthenticatorData>());
            Assert.That(result.Ok?.Flags, Is.EqualTo(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionDataIncluded));
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    // WebAuthn Level 3 §6.1: the extensions block "is a CBOR map with extension identifiers as keys, and authenticator extension outputs as values"
    [TestCase(new byte[] { 0x01 })] // unsigned integer 1
    [TestCase(new byte[] { 0x20 })] // negative integer -1
    [TestCase(new byte[] { 0x80 })] // empty array
    [TestCase(new byte[] { 0x40 })] // empty byte string
    [TestCase(new byte[] { 0x63, 0x61, 0x62, 0x63 })] // text string "abc"
    public void Decode_Fails_WhenExtensionsIsNotCborMap(byte[] extensions)
    {
        var authData = BuildAuthData(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionDataIncluded, null, extensions);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("'extensions' must be represented as a CBOR map"));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Failed to read 'extensions'"));
        });
    }

    // CTAP 2.2 §12.5 hmac-secret (the authenticator output behind the WebAuthn prf extension) and §12.3 credBlob
    // return a boolean makeCredential output inside the authData extensions, so a CBOR boolean must be decodable there
    [TestCase(true)]
    [TestCase(false)]
    public void Decode_Succeeds_WhenExtensionsContainHmacSecretBooleanOutput(bool hmacSecret)
    {
        // {"hmac-secret": <bool>}
        var extensions = Cbor(writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("hmac-secret");
            writer.WriteBoolean(hmacSecret);
            writer.WriteEndMap();
        });
        var authData = BuildAuthData(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionDataIncluded, null, extensions);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok, Is.InstanceOf<NotAttestedAuthenticatorData>());
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public void Decode_Succeeds_WhenExtensionsContainSeveralOutputsIncludingBooleans()
    {
        // {"credBlob": true, "credProtect": 2, "hmac-secret": true}
        var extensions = Cbor(static writer =>
        {
            writer.WriteStartMap(3);
            writer.WriteTextString("credBlob");
            writer.WriteBoolean(true);
            writer.WriteTextString("credProtect");
            writer.WriteInt32(2);
            writer.WriteTextString("hmac-secret");
            writer.WriteBoolean(true);
            writer.WriteEndMap();
        });
        var authData = BuildAuthData(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionDataIncluded, null, extensions);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public void Decode_Succeeds_WhenAttestedCredentialDataIsFollowedByExtensionsWithBooleanOutput()
    {
        // {"hmac-secret": true}
        var extensions = Cbor(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("hmac-secret");
            writer.WriteBoolean(true);
            writer.WriteEndMap();
        });
        var authData = BuildAuthData(
            AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.AttestedCredentialData | AuthenticatorDataFlags.ExtensionDataIncluded,
            BuildAttestedCredentialData(16),
            extensions);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok, Is.InstanceOf<AttestedAuthenticatorData>());
            Assert.That(result.Ok?.SignCount, Is.EqualTo(1u));
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    // floating-point values are not used in WebAuthn and stay unsupported
    [Test]
    public void Decode_Fails_WhenExtensionsContainFloat()
    {
        // {"x": 1.5}
        var extensions = Cbor(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("x");
            writer.WriteDouble(1.5);
            writer.WriteEndMap();
        });
        var authData = BuildAuthData(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionDataIncluded, null, extensions);

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Failed to read 'extensions'"));
        });
    }

    [Test]
    public void Decode_Fails_WhenDataRemainsAfterExtensions()
    {
        // {"hmac-secret": true} followed by one more byte
        var extensions = Cbor(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("hmac-secret");
            writer.WriteBoolean(true);
            writer.WriteEndMap();
        });
        var authData = BuildAuthData(AuthenticatorDataFlags.UserPresent | AuthenticatorDataFlags.ExtensionDataIncluded, null, extensions.Append((byte) 0x00).ToArray());

        var result = Decoder.Decode(authData);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("After decoding 'authData' in accordance with its structure, some data has been found to still remain within it"));
        });
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
    private static byte[] BuildAuthData(AuthenticatorDataFlags flags, byte[]? attestedCredentialData, byte[]? extensions)
    {
        var result = new List<byte>(37);
        result.AddRange(RpIdHash);
        result.Add((byte) flags);
        result.AddRange(SignCount);
        if (attestedCredentialData is not null)
        {
            result.AddRange(attestedCredentialData);
        }

        if (extensions is not null)
        {
            result.AddRange(extensions);
        }

        return result.ToArray();
    }

    // https://www.w3.org/TR/webauthn-3/#sctn-attested-credential-data
    private static byte[] BuildAttestedCredentialData(int credentialIdLength)
    {
        var credentialId = new byte[credentialIdLength];
        for (var i = 0; i < credentialId.Length; i++)
        {
            credentialId[i] = (byte) i;
        }

        var result = new List<byte>(16 + 2 + credentialIdLength + CoseKey.Length);
        result.AddRange(Aaguid);
        result.Add((byte) (credentialIdLength >> 8));
        result.Add((byte) credentialIdLength);
        result.AddRange(credentialId);
        result.AddRange(CoseKey);
        return result.ToArray();
    }

    // COSE_Key { 1: 2 (kty: EC2), 3: -7 (alg: ES256), -1: 1 (crv: P-256), -2: x, -3: y }
    private static byte[] CreateEs256CoseKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteInt32(-7);
        writer.WriteInt32(-1);
        writer.WriteInt32(1);
        writer.WriteInt32(-2);
        writer.WriteByteString(point.X!);
        writer.WriteInt32(-3);
        writer.WriteByteString(point.Y!);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] Cbor(Action<CborWriter> write)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        write(writer);
        return writer.Encode();
    }
}
