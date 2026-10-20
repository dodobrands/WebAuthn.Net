using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultAppleAnonymousAttestationStatementDecoderTests
{
    // the decoder only extracts the fields; their content is validated by the verifier, so a placeholder is enough here
    private static readonly byte[] Certificate = { 0x30, 0x00 };

    [Test]
    public void Decode_Succeeds_WhenX5CHasSixteenElements()
    {
        var logger = new FakeLogger<DefaultAppleAnonymousAttestationStatementDecoder>();
        var decoder = new DefaultAppleAnonymousAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(16));

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
        var logger = new FakeLogger<DefaultAppleAnonymousAttestationStatementDecoder>();
        var decoder = new DefaultAppleAnonymousAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(17));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Some.Contains("'x5c' array in the 'attStmt' contains 17 elements, which exceeds the maximum of 16"));
        });
    }

    private static CborMap CreateAttStmt(int x5CCount)
    {
        return new(new Dictionary<AbstractCborObject, AbstractCborObject>
        {
            [new CborTextString("x5c")] = new CborArray(Enumerable.Repeat<AbstractCborObject>(new CborByteString(Certificate), x5CCount))
        });
    }
}
