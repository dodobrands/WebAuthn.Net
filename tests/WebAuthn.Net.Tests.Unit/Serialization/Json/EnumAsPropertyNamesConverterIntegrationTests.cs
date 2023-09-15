using System.Runtime.Serialization;
using System.Text.Json;
using System.Text.Json.Serialization;
using NUnit.Framework;

namespace WebAuthn.Net.Serialization.Json;

public class EnumAsStringConverterIntegrationTests
{
    [TestCase(Fruit.Apple, "apple-fruit")]
    [TestCase(Fruit.Banana, "banana-fruit")]
    public void SerializeEnum(Fruit expectedValue, string expectedStringRepresentation)
    {
        var expected = new Dto
        {
            Fruit = expectedValue
        };

        var serialized = JsonSerializer.Serialize(expected);
        var neutrallyDeserialized = JsonSerializer.Deserialize<JsonDocument>(serialized);
        var x = neutrallyDeserialized!.RootElement.GetProperty("Fruit").GetString();
        Assert.That(x, Is.EqualTo(expectedStringRepresentation));
        var deserialized = JsonSerializer.Deserialize<Dto>(serialized);
        Assert.That(deserialized!.Fruit, Is.EqualTo(expectedValue));
    }

    [JsonConverter(typeof(EnumAsStringConverter<Fruit>))]
    public enum Fruit
    {
        [EnumMember(Value = "banana-fruit")]
        Banana,

        [EnumMember(Value = "apple-fruit")]
        Apple
    }


    private class Dto
    {
        public Fruit Fruit { get; set; }
    }
}
