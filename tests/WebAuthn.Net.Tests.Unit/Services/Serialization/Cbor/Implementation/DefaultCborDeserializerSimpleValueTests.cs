using System;
using System.Formats.Cbor;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.Implementation;

public class DefaultCborDeserializerSimpleValueTests
{
    private FakeLogger<DefaultCborDeserializer> Logger { get; set; } = null!;

    private DefaultCborDeserializer Deserializer { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Logger = new();
        Deserializer = new(Logger);
    }

    [TestCase(new byte[] { 0xf4 }, false)]
    [TestCase(new byte[] { 0xf5 }, true)]
    public void Deserialize_DecodesBoolean(byte[] cbor, bool expected)
    {
        var result = Deserializer.Deserialize(cbor);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Root, Is.InstanceOf<CborBoolean>());
            Assert.That(((CborBoolean) result.Ok!.Root).RawValue, Is.EqualTo(expected));
            Assert.That(result.Ok.BytesConsumed, Is.EqualTo(1));
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public void Deserialize_DecodesNull()
    {
        var result = Deserializer.Deserialize(new byte[] { 0xf6 });

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok?.Root, Is.InstanceOf<CborNull>());
            Assert.That(result.Ok?.BytesConsumed, Is.EqualTo(1));
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public void Deserialize_DecodesMapWithBooleanAndNullValues()
    {
        // {"a": true, "b": false, "c": null}
        var cbor = Cbor(static writer =>
        {
            writer.WriteStartMap(3);
            writer.WriteTextString("a");
            writer.WriteBoolean(true);
            writer.WriteTextString("b");
            writer.WriteBoolean(false);
            writer.WriteTextString("c");
            writer.WriteNull();
            writer.WriteEndMap();
        });

        var result = Deserializer.Deserialize(cbor);

        Assert.That(result.HasError, Is.False);
        var map = (CborMap) result.Ok!.Root;
        Assert.Multiple(() =>
        {
            Assert.That(map.RawValue, Has.Count.EqualTo(3));
            Assert.That(map.RawValue[new CborTextString("a")], Is.EqualTo(new CborBoolean(true)));
            Assert.That(map.RawValue[new CborTextString("b")], Is.EqualTo(new CborBoolean(false)));
            Assert.That(map.RawValue[new CborTextString("c")], Is.EqualTo(new CborNull()));
            Assert.That(result.Ok.BytesConsumed, Is.EqualTo(cbor.Length));
        });
    }

    [Test]
    public void Deserialize_DecodesMapWithBooleanKeys()
    {
        // {false: 0, true: 1} - the keys are looked up through CborBoolean equality and hashing
        var cbor = Cbor(static writer =>
        {
            writer.WriteStartMap(2);
            writer.WriteBoolean(false);
            writer.WriteInt32(0);
            writer.WriteBoolean(true);
            writer.WriteInt32(1);
            writer.WriteEndMap();
        });

        var result = Deserializer.Deserialize(cbor);

        Assert.That(result.HasError, Is.False);
        var map = (CborMap) result.Ok!.Root;
        Assert.Multiple(() =>
        {
            Assert.That(map.RawValue, Has.Count.EqualTo(2));
            Assert.That(map.RawValue[new CborBoolean(false)], Is.EqualTo(new CborUnsignedInteger(0)));
            Assert.That(map.RawValue[new CborBoolean(true)], Is.EqualTo(new CborUnsignedInteger(1)));
        });
    }

    [Test]
    public void Deserialize_DecodesArrayWithBooleanAndNullElements()
    {
        // [true, null, false]
        var cbor = Cbor(static writer =>
        {
            writer.WriteStartArray(3);
            writer.WriteBoolean(true);
            writer.WriteNull();
            writer.WriteBoolean(false);
            writer.WriteEndArray();
        });

        var result = Deserializer.Deserialize(cbor);

        Assert.That(result.HasError, Is.False);
        var array = (CborArray) result.Ok!.Root;
        Assert.That(array.RawValue, Is.EqualTo(new AbstractCborObject[] { new CborBoolean(true), new CborNull(), new CborBoolean(false) }));
    }

    // floating-point numbers and the simple values other than false, true and null are not used in WebAuthn and stay unsupported
    [TestCase(new byte[] { 0xf7 })] // undefined
    [TestCase(new byte[] { 0xf0 })] // simple value 16
    [TestCase(new byte[] { 0xf8, 0xff })] // simple value 255
    [TestCase(new byte[] { 0xf9, 0x3c, 0x00 })] // half-precision 1.0
    [TestCase(new byte[] { 0xfa, 0x47, 0xc3, 0x50, 0x00 })] // single-precision 100000.0
    [TestCase(new byte[] { 0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a })] // double-precision 1.1
    public void Deserialize_Fails_WhenSimpleValueIsUnsupported(byte[] cbor)
    {
        var result = Deserializer.Deserialize(cbor);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Attempt to read unsupported CBOR simple value"));
        });
    }

    [Test]
    public void Deserialize_Fails_WhenMapValueIsUnsupportedSimpleValue()
    {
        // {"a": undefined}
        var cbor = Cbor(static writer =>
        {
            writer.WriteStartMap(1);
            writer.WriteTextString("a");
            writer.WriteSimpleValue(CborSimpleValue.Undefined);
            writer.WriteEndMap();
        });

        var result = Deserializer.Deserialize(cbor);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("Attempt to read unsupported CBOR simple value"));
        });
    }

    private static byte[] Cbor(Action<CborWriter> write)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        write(writer);
        return writer.Encode();
    }
}
