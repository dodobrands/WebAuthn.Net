using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultTpmAttestationStatementDecoderTests
{
    // the decoder only extracts the fields; their content is validated by the verifier, so placeholders are enough here
    private static readonly byte[] AikCertificate = { 0x30, 0x00 };
    private static readonly byte[] Signature = { 0x01, 0x02, 0x03 };
    private static readonly byte[] CertInfo = { 0xff, 0x54, 0x43, 0x47 };
    private static readonly byte[] PubArea = { 0x00, 0x01, 0x00, 0x0B };

    [Test]
    public void Decode_Succeeds_WhenVerIsTwoPointZero()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var attStmt = CreateAttStmt(new CborTextString("2.0"));

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Ver, Is.EqualTo("2.0"));
            Assert.That(result.Ok?.Alg, Is.EqualTo(CoseAlgorithm.RS256));
            Assert.That(result.Ok?.X5C, Has.Length.EqualTo(1));
            Assert.That(result.Ok?.X5C[0], Is.EqualTo(AikCertificate));
            Assert.That(result.Ok?.Sig, Is.EqualTo(Signature));
            Assert.That(result.Ok?.CertInfo, Is.EqualTo(CertInfo));
            Assert.That(result.Ok?.PubArea, Is.EqualTo(PubArea));
            Assert.That(logger.Entries, Is.Empty);
        });
    }

    // WebAuthn Level 3 §8.3: tpmStmtFormat = { ver: "2.0", ... } - the CDDL fixes 'ver' to the literal "2.0"
    [TestCase("1.2")]
    [TestCase("2.0 ")]
    [TestCase(" 2.0")]
    [TestCase("2.00")]
    [TestCase("2")]
    [TestCase("")]
    public void Decode_Fails_WhenVerIsNotTwoPointZero(string ver)
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var attStmt = CreateAttStmt(new CborTextString(ver));

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo($"The 'ver' value in the 'attStmt' map is not supported: {ver}"));
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Failed to decode the 'ver' value from 'attStmt'"));
        });
    }

    [Test]
    public void Decode_Fails_WhenVerIsNotTextString()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var attStmt = CreateAttStmt(new CborUnsignedInteger(2));

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("The 'ver' value in the 'attStmt' map contains an invalid data type"));
        });
    }

    [Test]
    public void Decode_Fails_WhenVerIsMissing()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var attStmt = CreateAttStmt(null);

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Failed to find the 'ver' key in 'attStmt'"));
        });
    }

    [Test]
    public void Decode_TruncatesUnsupportedVer_InLogMessage()
    {
        // 'ver' is untrusted input: only its first 64 characters are logged
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var ver = new string('9', 200);

        var result = decoder.Decode(CreateAttStmt(new CborTextString(ver)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo($"The 'ver' value in the 'attStmt' map is not supported: {ver[..64]}..."));
        });
    }

    [TestCase("alg", "Failed to find the 'alg' key in 'attStmt'")]
    [TestCase("sig", "Failed to find the 'sig' key in 'attStmt'")]
    [TestCase("x5c", "Failed to find the 'x5c' key in 'attStmt'")]
    [TestCase("pubArea", "Failed to find the key 'pubArea' in 'attStmt'")]
    [TestCase("certInfo", "Failed to find the key 'certInfo' in 'attStmt'")]
    public void Decode_Fails_WhenMemberIsMissing(string key, string expectedMessage)
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(new CborTextString("2.0"), key));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo(expectedMessage));
        });
    }

    [TestCase("alg", "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    [TestCase("sig", "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    [TestCase("x5c", "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    [TestCase("pubArea", "An invalid data type is used for the 'pubArea' value in 'attStmt'")]
    [TestCase("certInfo", "An invalid data type is used for the 'certInfo' value in 'attStmt'")]
    public void Decode_Fails_WhenMemberHasInvalidDataType(string key, string expectedMessage)
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(new CborTextString("2.0"), replace: (key, new CborTextString("invalid"))));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo(expectedMessage));
        });
    }

    [Test]
    public void Decode_Fails_WhenX5CElementIsNotByteString()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);
        var x5C = new CborArray(new AbstractCborObject[] { new CborByteString(AikCertificate), new CborTextString("certificate") });

        var result = decoder.Decode(CreateAttStmt(new CborTextString("2.0"), replace: ("x5c", x5C)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type"));
        });
    }

    [Test]
    public void Decode_Fails_WhenAlgIsUnknown()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(new CborTextString("2.0"), replace: ("alg", new CborNegativeInteger(-9999))));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("The 'attStmt' contains an unknown 'alg': -9999"));
        });
    }

    [Test]
    public void Decode_Fails_WhenAlgIsOutOfInt32Range()
    {
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(new CborTextString("2.0"), replace: ("alg", new CborUnsignedInteger(ulong.MaxValue))));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("The 'alg' value in the 'attStmt' map is out of range"));
        });
    }

    [Test]
    public void Decode_Succeeds_WhenX5CIsEmpty()
    {
        // the decoder only checks the data types; the verifier rejects an empty x5c ("Verify that x5c is present")
        var logger = new FakeLogger<DefaultTpmAttestationStatementDecoder>();
        var decoder = new DefaultTpmAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(new CborTextString("2.0"), replace: ("x5c", new CborArray(System.Array.Empty<AbstractCborObject>()))));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.X5C, Is.Empty);
        });
    }

    private static CborMap CreateAttStmt(AbstractCborObject? ver, string? remove = null, (string Key, AbstractCborObject Value)? replace = null)
    {
        var values = new Dictionary<AbstractCborObject, AbstractCborObject>
        {
            // RS256
            { new CborTextString("alg"), new CborNegativeInteger(-257) },
            { new CborTextString("x5c"), new CborArray(new AbstractCborObject[] { new CborByteString(AikCertificate) }) },
            { new CborTextString("sig"), new CborByteString(Signature) },
            { new CborTextString("certInfo"), new CborByteString(CertInfo) },
            { new CborTextString("pubArea"), new CborByteString(PubArea) }
        };
        if (ver is not null)
        {
            values.Add(new CborTextString("ver"), ver);
        }

        if (remove is not null)
        {
            values.Remove(new CborTextString(remove));
        }

        if (replace.HasValue)
        {
            values[new CborTextString(replace.Value.Key)] = replace.Value.Value;
        }

        return new(values);
    }
}
