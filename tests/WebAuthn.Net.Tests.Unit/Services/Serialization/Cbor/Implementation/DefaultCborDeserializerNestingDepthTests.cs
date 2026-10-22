using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;

namespace WebAuthn.Net.Services.Serialization.Cbor.Implementation;

public class DefaultCborDeserializerNestingDepthTests
{
    private FakeLogger<DefaultCborDeserializer> Logger { get; set; } = null!;

    private DefaultCborDeserializer Deserializer { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Logger = new();
        Deserializer = new(Logger);
    }

    // the nesting depth counts every item level: the outermost array is level 1 and the innermost (empty) array of 32 nested arrays is level 32, the limit
    [TestCase(1)]
    [TestCase(2)]
    [TestCase(32)]
    public void Deserialize_DecodesNestedArrays_WhenNestingIsWithinLimit(int arrays)
    {
        var result = Deserializer.Deserialize(NestedArrays(arrays));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    // Without the limit, the recursive descent overflows the stack for a few thousand levels, which terminates the process instead of failing
    // (System.Formats.Cbor checks the depth itself only since ASP.NET Core 10.0.13, 64 levels by default). These depths are above the limit
    // but below the default depth limit of System.Formats.Cbor, so the limit - and nothing else - is what stops the decoding here.
    [TestCase(33)]
    [TestCase(60)]
    public void Deserialize_Fails_WhenNestedArraysExceedLimit(int arrays)
    {
        var result = Deserializer.Deserialize(NestedArrays(arrays));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("The nesting depth of the CBOR data exceeds the maximum limit of 32"));
        });
    }

    // {0: {0: ... {0: 0} ... }}: the maps are levels 1..N and the innermost integer is level N + 1, so 31 maps are the limit
    [TestCase(1)]
    [TestCase(31)]
    public void Deserialize_DecodesNestedMaps_WhenNestingIsWithinLimit(int maps)
    {
        var result = Deserializer.Deserialize(NestedMaps(maps));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [TestCase(32)]
    [TestCase(60)]
    public void Deserialize_Fails_WhenNestedMapsExceedLimit(int maps)
    {
        var result = Deserializer.Deserialize(NestedMaps(maps));

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Level), Has.All.EqualTo(LogLevel.Warning));
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.Some.EqualTo("The nesting depth of the CBOR data exceeds the maximum limit of 32"));
        });
    }

    // Regression test for the stack overflow itself. System.Formats.Cbor stops such input only since ASP.NET Core 10.0.13 and only as long as its depth limit
    // is not raised for the whole process (the System.Formats.Cbor.CborReader.MaxDepth AppContext switch), so the limit has to stop it on its own.
    [TestCase(100_000)]
    public void Deserialize_Fails_WhenNestingIsVeryDeep(int levels)
    {
        var arrays = Deserializer.Deserialize(NestedArrays(levels));
        var maps = Deserializer.Deserialize(NestedMaps(levels));

        Assert.Multiple(() =>
        {
            Assert.That(arrays.HasError, Is.True);
            Assert.That(maps.HasError, Is.True);
            Assert.That(Logger.Entries.Select(static x => x.Message), Has.All.EqualTo("The nesting depth of the CBOR data exceeds the maximum limit of 32"));
        });
    }

    // [[[ ... [] ... ]]] - 0x81 = array(1), 0x80 = array(0)
    private static byte[] NestedArrays(int arrays)
    {
        var result = new byte[arrays];
        Array.Fill(result, (byte) 0x81);
        result[^1] = 0x80;
        return result;
    }

    // {0: {0: ... {0: 0} ... }} - 0xa1 0x00 = map(1) with the key 0, the innermost value is the integer 0
    private static byte[] NestedMaps(int maps)
    {
        var result = new byte[(maps * 2) + 1];
        for (var i = 0; i < maps; i++)
        {
            result[i * 2] = 0xa1;
            result[(i * 2) + 1] = 0x00;
        }

        result[^1] = 0x00;
        return result;
    }
}
