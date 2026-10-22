using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed.Constants;
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
        var decoder = new DefaultPackedAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

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
        var decoder = new DefaultPackedAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);
        var attStmt = CreateAttStmt(x5CCount: 1, (new CborTextString("ecdaaKeyId"), new CborByteString(new byte[] { 0x01 })));

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Is.EqualTo(new[] { UnknownMembersWarning(1, "'ecdaaKeyId'") }));
        });
    }

    [Test]
    public void Decode_Succeeds_AndLogsWarning_WhenAttStmtContainsUnknownNonTextKey()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);
        var attStmt = CreateAttStmt(x5CCount: 1, (new CborUnsignedInteger(1), new CborByteString(new byte[] { 0x01 })));

        var result = decoder.Decode(attStmt);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Is.EqualTo(new[] { UnknownMembersWarning(1, "<UnsignedInteger>") }));
        });
    }

    // The unknown members are chosen by the client and reported before any signature is verified: however many there are,
    // they are reported with a single Warning that contains their number and the keys of at most 8 of them

    [Test]
    public void Decode_Succeeds_AndListsEveryUnknownMemberInOneWarning_WhenAttStmtContainsEightUnknownMembers()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 1, UnknownMembers(8)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Select(static x => x.Message),
                Is.EqualTo(new[] { UnknownMembersWarning(8, "'m0', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7'") }));
        });
    }

    [TestCase(9)]
    [TestCase(10_000)]
    public void Decode_Succeeds_AndListsOnlyEightUnknownMembersInOneWarning_WhenAttStmtContainsMoreUnknownMembers(int count)
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 1, UnknownMembers(count)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Select(static x => x.Message),
                Is.EqualTo(new[] { UnknownMembersWarning(count, "'m0', 'm1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', ...") }));
        });
    }

    // the members outside the syntax are a tolerated anomaly, counted once per attestation statement however many of them there are

    [TestCase(1)]
    [TestCase(9)]
    [TestCase(10_000)]
    public void Decode_CountsOneToleratedAnomaly_WhenAttStmtContainsUnknownMembers(int count)
    {
        var counters = new FakeRegistrationCeremonyCounters();
        var decoder = new DefaultPackedAttestationStatementDecoder(counters, new FakeLogger<DefaultPackedAttestationStatementDecoder>());

        var result = decoder.Decode(CreateAttStmt(x5CCount: 1, UnknownMembers(count)));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                counters.AttestationStatementAnomalies,
                Is.EqualTo(new[] { new FakeAttestationStatementAnomaly(PackedAttestationStatementAnomalies.Format, PackedAttestationStatementAnomalies.AttStmtMemberOutsideSyntax, true) }));
        });
    }

    [Test]
    public void Decode_CountsNoAnomaly_ForWellFormedAttStmt()
    {
        var counters = new FakeRegistrationCeremonyCounters();
        var decoder = new DefaultPackedAttestationStatementDecoder(counters, new FakeLogger<DefaultPackedAttestationStatementDecoder>());

        var result = decoder.Decode(CreateAttStmt(x5CCount: 2));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(counters.AttestationStatementAnomalies, Is.Empty);
        });
    }

    [Test]
    public void Decode_Succeeds_WhenX5CHasSixteenElements()
    {
        var logger = new FakeLogger<DefaultPackedAttestationStatementDecoder>();
        var decoder = new DefaultPackedAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

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
        var decoder = new DefaultPackedAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 17));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Some.Contains("'x5c' array in the 'attStmt' contains 17 elements, which exceeds the maximum of 16"));
        });
    }

    private static string UnknownMembersWarning(int count, string members)
    {
        return $"The 'attStmt' of the Packed attestation statement contains {count.ToString(CultureInfo.InvariantCulture)} member(s) that are not defined by its CDDL (alg, sig, x5c); they are ignored: {members}";
    }

    private static (AbstractCborObject Key, AbstractCborObject Value)[] UnknownMembers(int count)
    {
        return Enumerable.Range(0, count)
            .Select(static i => ((AbstractCborObject) new CborTextString("m" + i.ToString(CultureInfo.InvariantCulture)), (AbstractCborObject) new CborUnsignedInteger((ulong) i)))
            .ToArray();
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
