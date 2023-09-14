using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Serialization.Json;

public sealed class EnumValueAttributeConverter<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] T> : JsonConverter<T>
    where T : struct, Enum
{
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var text = reader.GetString();

        if (text is null)
        {
            throw new JsonException("Expected enum name");
        }

        if (EnumNameMapper<T>.TryGetValue(text, out var value))
        {
            return value;
        }

        throw new JsonException($"Invalid enum value = {text}");
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(EnumNameMapper<T>.GetName(value));
    }
}
