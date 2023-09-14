using System;
using System.Linq;
using System.Text.Json;
using NUnit.Framework;

namespace WebAuthn.Net.Serialization.Json;

public class Base64UrlConverterIntegrationTests
{
    class Dto
    {
        [System.Text.Json.Serialization.JsonConverter(typeof(Base64UrlConverter))]
        public byte[] Bytes { get; set; } = Array.Empty<byte>();
    }

    [TestCase(new byte[] {0, 0, 62, 0, 0, 63}, "AAA-AAA_")]
    public void SerializesBinary(byte[] bytes, string expectedStringRepresentation)
    {
        var expected = new Dto { Bytes = bytes.ToArray() };
        var serialized = JsonSerializer.Serialize(expected);
        var neutrallyDeserialized = JsonSerializer.Deserialize<JsonDocument>(serialized);
        var x = neutrallyDeserialized!.RootElement.GetProperty("Bytes").GetString();
        Assert.That(x, Is.EqualTo(expectedStringRepresentation));
        var deserialized = JsonSerializer.Deserialize<Dto>(serialized);
        Assert.That(deserialized!.Bytes, Is.EqualTo(bytes));
    }
}
