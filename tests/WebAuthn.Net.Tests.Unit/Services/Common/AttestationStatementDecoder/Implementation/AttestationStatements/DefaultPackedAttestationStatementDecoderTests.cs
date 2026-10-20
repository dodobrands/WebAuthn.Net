using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultPackedAttestationStatementDecoderTests
{
    // the decoder only extracts the fields; their content is validated by the verifier, so placeholders are enough here
    private static readonly byte[] Certificate = { 0x30, 0x00 };
    private static readonly byte[] Signature = { 0x01, 0x02, 0x03 };

    [Test]
    public void Decode_Succeeds_WithoutWarnings_ForWellFormedAttStmt()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 2));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Alg, Is.EqualTo(CoseAlgorithm.ES256));
            Assert.That(result.Ok?.Sig, Is.EqualTo(Signature));
            Assert.That(result.Ok?.X5C, Has.Length.EqualTo(2));
            Assert.That(logger.Entries, Is.Empty);
        });
    }

    // WebAuthn Level 3 §8.2: packedStmtFormat is a closed map (alg, sig, x5c); unknown members are tolerated for interoperability but reported
    [Test]
    public void Decode_Succeeds_AndLogsWarning_WhenAttStmtContainsUnknownMember()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(logger);
        var attStmt = CreateAttStmt(x5CCount: 1, (new CborTextString("ecdaaKeyId"), new CborByteString(new byte[] { 0x01 })));

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).Contains("contains a member that is not defined by its CDDL (alg, sig, x5c); the member is ignored: ecdaaKeyId"));
        });
    }

    [Test]
    public void Decode_Succeeds_AndLogsWarning_WhenAttStmtContainsUnknownNonTextKey()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(logger);
        var attStmt = CreateAttStmt(x5CCount: 1, (new CborUnsignedInteger(1), new CborByteString(new byte[] { 0x01 })));

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).Contains("the member is ignored: UnsignedInteger"));
        });
    }

    [Test]
    public void Decode_Succeeds_WhenX5CHasSixteenElements()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 16));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.X5C, Has.Length.EqualTo(16));
            Assert.That(logger.Entries, Is.Empty);
        });
    }

    [Test]
    public void Decode_Fails_WhenX5CHasMoreThanSixteenElements()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 17));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Some.Contains("'x5c' array in the 'attStmt' contains 17 elements, which exceeds the maximum of 16"));
        });
    }

    private static CborMap CreateAttStmt(int x5CCount, params (AbstractCborObject Key, AbstractCborObject Value)[] extraMembers)
    {
        var members = new Dictionary<AbstractCborObject, AbstractCborObject>
        {
            [new CborTextString("alg")] = new CborNegativeInteger((int) CoseAlgorithm.ES256),
            [new CborTextString("sig")] = new CborByteString(Signature),
            [new CborTextString("x5c")] = new CborArray(Enumerable.Repeat<AbstractCborObject>(new CborByteString(Certificate), x5CCount))
        };
        foreach (var (key, value) in extraMembers)
        {
            members[key] = value;
        }

        return new(members);
    }
}
