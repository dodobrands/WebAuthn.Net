using System;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.DSL;

namespace WebAuthn.Net.Services.Serialization.Cbor.Implementation;

public class DefaultCborDeserializerTests
{
    [TestCaseSource(nameof(GetSuccessfulTestVectors))]
    public void DefaultCborDeserializer_DecodesWithoutError_WhenCorrectDataOnInput(TestVector testVector)
    {
        ArgumentNullException.ThrowIfNull(testVector);
        var decoder = new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance);
        var decodeResult = decoder.Deserialize(testVector.Cbor);
        Assert.That(decodeResult.HasError, Is.False);
    }

    [TestCaseSource(nameof(GetFailedTestVectors))]
    public void DefaultCborDeserializer_DecodesWithError_WhenIncorrectDataOnInput(TestVector testVector)
    {
        ArgumentNullException.ThrowIfNull(testVector);
        var decoder = new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance);
        var decodeResult = decoder.Deserialize(testVector.Cbor);
        Assert.That(decodeResult.HasError, Is.True);
    }

    [Test]
    public void DefaultCborDeserializer_DecodesWithError_WhenMalformedDataOnInput()
    {
        var decoder = new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance);
        var decodeResult = decoder.Deserialize(new byte[]
        {
            0xf8,
            0x18
        });
        Assert.That(decodeResult.HasError, Is.True);
    }

    public static TestVector[] GetSuccessfulTestVectors()
    {
        var result = JsonSerializer.Deserialize<JsonTestVector[]>(SuccessfulTestVectors());
        if (result is null)
        {
            throw new InvalidOperationException("Failed to retrieve the test vectors from the embedded resource");
        }

        return result.Select(x => x.ToTestVector()).ToArray();
    }

    public static TestVector[] GetFailedTestVectors()
    {
        var result = JsonSerializer.Deserialize<JsonTestVector[]>(FailedTestVectors());
        if (result is null)
        {
            throw new InvalidOperationException("Failed to retrieve the test vectors from the embedded resource");
        }

        return result.Select(x => x.ToTestVector()).ToArray();
    }

    private static string SuccessfulTestVectors()
    {
        return EmbeddedResourceProvider.GetString("WebAuthn.Net.Services.Serialization.Cbor.Implementation.SuccessfulTestVectors.json");
    }

    private static string FailedTestVectors()
    {
        return EmbeddedResourceProvider.GetString("WebAuthn.Net.Services.Serialization.Cbor.Implementation.FailedTestVectors.json");
    }

    private sealed class JsonTestVector
    {
        [JsonConstructor]
        public JsonTestVector(string hex, bool roundtrip, JsonElement decoded)
        {
            Hex = hex;
            Roundtrip = roundtrip;
            Decoded = decoded;
        }

        [JsonPropertyName("hex")]
        public string Hex { get; }

        [JsonPropertyName("roundtrip")]
        public bool Roundtrip { get; }

        [JsonPropertyName("decoded")]
        public JsonElement Decoded { get; }

        public TestVector ToTestVector()
        {
            var cbor = Convert.FromHexString(Hex);
            return new(cbor, Decoded, Hex);
        }
    }

    public class TestVector
    {
        public TestVector(byte[] cbor, JsonElement decoded, string hex)
        {
            Cbor = cbor;
            Decoded = decoded;
            Hex = hex;
        }

        public byte[] Cbor { get; }

        public JsonElement Decoded { get; }

        public string Hex { get; }

        public override string ToString()
        {
            return Hex;
        }
    }
}
