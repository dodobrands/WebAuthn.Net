using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultFidoU2FAttestationStatementDecoderTests
{
    // the decoder only extracts the fields; their content is validated by the verifier, so placeholders are enough here
    private static readonly byte[] Certificate = { 0x30, 0x00 };
    private static readonly byte[] Signature = { 0x01, 0x02, 0x03 };

    [Test]
    public void Decode_Succeeds_WhenX5CHasExactlyOneElement()
    {
        var logger = new FakeLogger<DefaultFidoU2FAttestationStatementDecoder>();
        var decoder = new DefaultFidoU2FAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(1));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Sig, Is.EqualTo(Signature));
            Assert.That(result.Ok?.X5C, Has.Length.EqualTo(1));
            Assert.That(logger.Entries, Is.Empty);
        });
    }

    // WebAuthn Level 3 §8.6: x5c is "a single element array containing the attestation certificate"
    [TestCase(0)]
    [TestCase(2)]
    public void Decode_Fails_WithSpecificWarning_WhenX5CDoesNotHaveExactlyOneElement(int x5CCount)
    {
        var logger = new FakeLogger<DefaultFidoU2FAttestationStatementDecoder>();
        var decoder = new DefaultFidoU2FAttestationStatementDecoder(logger);

        var result = decoder.Decode(CreateAttStmt(x5CCount));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(
                logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Some.Contains($"'x5c' array in the 'attStmt' contains {x5CCount} elements, but the FIDO U2F attestation statement requires exactly one"));
        });
    }

    private static CborMap CreateAttStmt(int x5CCount)
    {
        return new(new Dictionary<AbstractCborObject, AbstractCborObject>
        {
            [new CborTextString("sig")] = new CborByteString(Signature),
            [new CborTextString("x5c")] = new CborArray(Enumerable.Repeat<AbstractCborObject>(new CborByteString(Certificate), x5CCount))
        });
    }
}
