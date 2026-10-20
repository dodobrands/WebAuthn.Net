using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

// Regression tests for the hardening of DefaultTpmAttestationStatementDecoder: the length of 'x5c' is bounded, members outside the tpmStmtFormat syntax are reported,
// and untrusted strings are neutralized before they are written to a log message.
public class DefaultTpmAttestationStatementDecoderHardeningTests
{
    // the decoder only extracts the fields; their content is validated by the verifier, so placeholders are enough here
    private static readonly byte[] AikCertificate = { 0x30, 0x00 };
    private static readonly byte[] Signature = { 0x01, 0x02, 0x03 };
    private static readonly byte[] CertInfo = { 0xff, 0x54, 0x43, 0x47 };
    private static readonly byte[] PubArea = { 0x00, 0x01, 0x00, 0x0B };

    private static readonly string[] ExpectedMemberOutsideSyntaxWarnings =
    {
        "The 'attStmt' map contains a member that is not defined by the tpmStmtFormat syntax: 'ecdaaKeyId'; ignored",
        "The 'attStmt' map contains a member that is not defined by the tpmStmtFormat syntax: <UnsignedInteger>; ignored"
    };

    // ---------------------------------------------------------------------------------------------
    // The length of x5c is bounded

    [TestCase(1)]
    [TestCase(2)] // Windows Hello: aikCert and one intermediate CA certificate
    [TestCase(16)]
    public void Decode_Succeeds_WhenX5CHasAtMostSixteenElements(int count)
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(x5C: X5C(count)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.X5C, Has.Length.EqualTo(count));
            Assert.That(logger.Entries, Is.Empty);
        });
    }

    [TestCase(17)]
    [TestCase(1000)]
    public void Decode_Fails_WhenX5CHasMoreThanSixteenElements(int count)
    {
        // every element of x5c is later loaded as a certificate and handed to the chain builder, which is costly for attacker-controlled bytes, so the length is bounded;
        // only the count is logged, never the content of the elements
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(x5C: X5C(count)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(
                logger.Entries.Select(static x => x.Message),
                Has.Some.EqualTo(string.Create(CultureInfo.InvariantCulture, $"The 'x5c' array in the 'attStmt' map has {count} elements, more than the 16 that are accepted")));
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Failed to decode the 'x5c' value from 'attStmt'"));
            Assert.That(logger.Entries, Has.Count.EqualTo(2));
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Members outside the tpmStmtFormat syntax are ignored, but reported

    [Test]
    public void Decode_Succeeds_AndLogsWarning_ForEachMemberOutsideTheSyntax()
    {
        // tpmStmtFormat is a closed map: e.g. the ecdaaKeyId of WebAuthn Level 2 (ECDAA attestation was removed in Level 3) is not part of it, nor is a key of another data type
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var attStmt = CreateAttStmt(extra: new (AbstractCborObject Key, AbstractCborObject Value)[]
        {
            (new CborTextString("ecdaaKeyId"), new CborByteString(new byte[] { 0x00 })),
            (new CborUnsignedInteger(1), new CborTextString("one"))
        });

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Ver, Is.EqualTo("2.0"));
            Assert.That(result.Ok?.Alg, Is.EqualTo(CoseAlgorithm.RS256));
            Assert.That(result.Ok?.X5C, Has.Length.EqualTo(1));
            Assert.That(result.Ok?.Sig, Is.EqualTo(Signature));
            Assert.That(result.Ok?.CertInfo, Is.EqualTo(CertInfo));
            Assert.That(result.Ok?.PubArea, Is.EqualTo(PubArea));
            Assert.That(logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(logger.Entries.Select(static x => x.Message), Is.EquivalentTo(ExpectedMemberOutsideSyntaxWarnings));
        });
    }

    [Test]
    public void Decode_Succeeds_WithoutWarning_WhenOnlyTheSixMembersOfTheSyntaxArePresent()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt());

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(logger.Entries, Is.Empty);
        });
    }

    [Test]
    public void Decode_NeutralizesAndTruncatesKeyOfMemberOutsideTheSyntax_InLogMessage()
    {
        // the key is untrusted input: control characters are replaced by '?' and only the first 64 characters are logged
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var key = "ecdaa\r\nKeyId" + new string('\u001b', 100);

        var result = decoder.Decode(CreateAttStmt(extra: new (AbstractCborObject Key, AbstractCborObject Value)[] { (new CborTextString(key), new CborByteString(new byte[] { 0x00 })) }));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Select(static x => x.Message),
                Has.Some.EqualTo($"The 'attStmt' map contains a member that is not defined by the tpmStmtFormat syntax: 'ecdaa??KeyId{new string('?', 52)}...'; ignored"));
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The 'ver' value is untrusted input: control characters are neutralized, the length is bounded

    [Test]
    public void Decode_NeutralizesControlCharacters_WhenLoggingUnsupportedVer()
    {
        // CR LF would forge a log line and ESC start an escape sequence in a text sink, U+2028 (LINE SEPARATOR) is rendered as a line break by some sinks
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt("2.0\r\n2026-10-19 00:00:00 [INF] forged line \u001b[31m\u2028"));

        var messages = logger.Entries.Select(static x => x.Message).ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(messages, Has.Some.EqualTo("The 'ver' value in the 'attStmt' map is not supported: 2.0??2026-10-19 00:00:00 [INF] forged line ?[31m?"));
            AssertNoControlCharacters(messages);
        });
    }

    [Test]
    public void Decode_TruncatesAndNeutralizesUnsupportedVer_InLogMessage()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(new string('\n', 200)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo($"The 'ver' value in the 'attStmt' map is not supported: {new string('?', 64)}..."));
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static CborMap CreateAttStmt(
        string ver = "2.0",
        CborArray? x5C = null,
        IEnumerable<(AbstractCborObject Key, AbstractCborObject Value)>? extra = null)
    {
        var values = new Dictionary<AbstractCborObject, AbstractCborObject>
        {
            { new CborTextString("ver"), new CborTextString(ver) },
            // RS256
            { new CborTextString("alg"), new CborNegativeInteger(-257) },
            { new CborTextString("x5c"), x5C ?? X5C(1) },
            { new CborTextString("sig"), new CborByteString(Signature) },
            { new CborTextString("certInfo"), new CborByteString(CertInfo) },
            { new CborTextString("pubArea"), new CborByteString(PubArea) }
        };
        foreach (var (key, value) in extra ?? Array.Empty<(AbstractCborObject, AbstractCborObject)>())
        {
            values.Add(key, value);
        }

        return new(values);
    }

    private static CborArray X5C(int count)
    {
        return new(Enumerable.Repeat<AbstractCborObject>(new CborByteString(AikCertificate), count).ToArray());
    }

    // an ordinal check: the culture-sensitive string comparison of NUnit's Contains treats some control characters (e.g. ESC) as ignorable
    private static void AssertNoControlCharacters(IEnumerable<string> messages)
    {
        Assert.That(
            messages,
            Has.All.Matches<string>(static message => message is not null && !message.Any(static character => char.IsControl(character) || character is '\u2028' or '\u2029')),
            "expected no control character, line separator or paragraph separator in any log message");
    }
}
