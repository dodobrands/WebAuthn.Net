using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.Common.AttestationObjectDecoder.Implementation;

public class DefaultAttestationObjectDecoderTests
{
    // rpIdHash | flags (UP) | signCount
    private static readonly byte[] AuthData = SHA256.HashData("example.com"u8).Concat(new byte[] { 0x01, 0x00, 0x00, 0x00, 0x01 }).ToArray();
    private static readonly byte[] AttestationObject = BuildAttestationObject("none");

    private FakeLogger<DefaultAttestationObjectDecoder> Logger { get; set; } = null!;

    private DefaultAttestationObjectDecoder Decoder { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Logger = new();
        Decoder = new(
            new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance),
            new DefaultEnumMemberAttributeSerializer<AttestationStatementFormat>(),
            Logger);
    }

    [Test]
    public void Decode_Succeeds_WhenAttestationObjectIsASingleCborItem()
    {
        var result = Decoder.Decode(AttestationObject);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Fmt, Is.EqualTo(AttestationStatementFormat.None));
            Assert.That(result.Ok?.AttStmt.RawValue, Is.Empty);
            Assert.That(result.Ok?.AuthData, Is.EqualTo(AuthData));
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    // CTAP 2.2 §8: a message in the CTAP2 canonical CBOR encoding form is a single data item - whatever follows it is not part of the attestation object
    // and is not covered by the attestation signature, so it is rejected instead of being silently ignored
    [TestCase(new byte[] { 0x00 })] // unsigned integer 0
    [TestCase(new byte[] { 0xa0 })] // empty map
    [TestCase(new byte[] { 0xff })] // "break" stop code
    [TestCase(new byte[] { 0x01, 0x02, 0x03 })]
    public void Decode_Fails_WhenTrailingDataFollowsTheAttestationObject(byte[] trailingData)
    {
        var attestationObject = AttestationObject.Concat(trailingData).ToArray();

        var result = Decoder.Decode(attestationObject);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("After decoding 'attestationObject' in accordance with its structure, some data has been found to still remain within it"));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Error attempting to read the byte representation of 'attestationObject' as a CBOR map"));
        });
    }

    [Test]
    public void Decode_Fails_WhenAttestationObjectIsTruncated()
    {
        var attestationObject = AttestationObject.Take(AttestationObject.Length - 1).ToArray();

        var result = Decoder.Decode(attestationObject);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Failed to decode 'attestationObject' from CBOR"));
        });
    }

    // The SafetyNet Attestation API has been turned down, and WebAuthn Level 3 deprecates the "android-safetynet" format, so it is not supported
    [Test]
    public void Decode_Fails_WhenFmtIsAndroidSafetyNet()
    {
        var attestationObject = BuildAttestationObject("android-safetynet");

        var result = Decoder.Decode(attestationObject);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("The 'fmt' key in the 'attestationObject' map has an unknown attestation statement format: android-safetynet"));
        });
    }

    // {"fmt": <fmt>, "attStmt": {}, "authData": <authData>}
    private static byte[] BuildAttestationObject(string fmt)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt");
        writer.WriteTextString(fmt);
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteTextString("authData");
        writer.WriteByteString(AuthData);
        writer.WriteEndMap();
        return writer.Encode();
    }
}
