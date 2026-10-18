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

    private static CborMap CreateAttStmt(AbstractCborObject? ver)
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

        return new(values);
    }
}
