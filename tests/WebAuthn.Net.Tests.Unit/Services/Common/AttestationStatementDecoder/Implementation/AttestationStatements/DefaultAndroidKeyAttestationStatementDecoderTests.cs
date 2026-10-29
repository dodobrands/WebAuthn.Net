using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey.Constants;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultAndroidKeyAttestationStatementDecoderTests
{
    // the decoder only extracts the fields; their content is validated by the verifier, so placeholders are enough here
    private static readonly byte[] Certificate = { 0x30, 0x00 };
    private static readonly byte[] Signature = { 0x01, 0x02, 0x03 };

    [Test]
    public void Decode_Succeeds_WithoutWarnings_ForWellFormedAttStmt()
    {
        var counters = new FakeRegistrationCeremonyCounters();
        var logger = new FakeLogger<DefaultAndroidKeyAttestationStatementDecoder>();
        var decoder = new DefaultAndroidKeyAttestationStatementDecoder(counters, logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 2));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Alg, Is.EqualTo(CoseAlgorithm.ES256));
            Assert.That(result.Ok?.Sig, Is.EqualTo(Signature));
            Assert.That(result.Ok?.X5C, Has.Length.EqualTo(2));
            Assert.That(logger.Entries, Is.Empty);
            Assert.That(counters.AttestationStatementAnomalies, Is.Empty);
        });
    }

    // WebAuthn Level 3 §8.4: androidStmtFormat is a closed map (alg, sig, x5c); unknown members are tolerated like in the other formats, but reported and counted once per attestation statement

    [TestCase(1)]
    [TestCase(9)]
    public void Decode_Succeeds_AndReportsAnomaly_WhenAttStmtContainsUnknownMembers(int count)
    {
        var counters = new FakeRegistrationCeremonyCounters();
        var logger = new FakeLogger<DefaultAndroidKeyAttestationStatementDecoder>();
        var decoder = new DefaultAndroidKeyAttestationStatementDecoder(counters, logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 1, UnknownMembers(count)));

        var listed = string.Join(", ", Enumerable.Range(0, Math.Min(count, 8)).Select(static i => $"'m{i.ToString(CultureInfo.InvariantCulture)}'")) + (count > 8 ? ", ..." : "");
        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Is.EqualTo(new[] { $"The 'attStmt' of the Android Key attestation statement contains {count.ToString(CultureInfo.InvariantCulture)} member(s) that are not defined by its CDDL (alg, sig, x5c); they are ignored: {listed}" }));
            Assert.That(
                counters.AttestationStatementAnomalies,
                Is.EqualTo(new[] { new FakeAttestationStatementAnomaly(AndroidKeyAttestationStatementAnomalies.Format, AndroidKeyAttestationStatementAnomalies.AttStmtMemberOutsideSyntax, true) }));
        });
    }

    [Test]
    public void Decode_Fails_WhenX5CIsEmpty()
    {
        // x5c: [ credCert: bytes, * (caCert: bytes) ] - the syntax requires credCert
        var logger = new FakeLogger<DefaultAndroidKeyAttestationStatementDecoder>();
        var decoder = new DefaultAndroidKeyAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 0));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Some.EqualTo("The 'x5c' array in the 'attStmt' is empty, but it must contain at least credCert"));
        });
    }

    [Test]
    public void Decode_Succeeds_WhenX5CHasSixteenElements()
    {
        var logger = new FakeLogger<DefaultAndroidKeyAttestationStatementDecoder>();
        var decoder = new DefaultAndroidKeyAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

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
        var logger = new FakeLogger<DefaultAndroidKeyAttestationStatementDecoder>();
        var decoder = new DefaultAndroidKeyAttestationStatementDecoder(new FakeRegistrationCeremonyCounters(), logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount: 17));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Some.Contains("'x5c' array in the 'attStmt' contains 17 elements, which exceeds the maximum of 16"));
        });
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
