using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.WebUtilities;

namespace WebAuthn.Net.Serialization.Json;

public class Base64UrlConverter : JsonConverter<byte[]>
{
    public override byte[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
        {
            return null;
        }

        if (reader.TokenType != JsonTokenType.String)
        {
            throw new InvalidOperationException($"Cannot get the value of a token type '{reader.TokenType}' as a string.");
        }

        var encodedString = reader.GetString();
        if (encodedString is null)
        {
            return null;
        }

        return WebEncoders.Base64UrlDecode(encodedString);
    }

    public override void Write(Utf8JsonWriter writer, byte[]? value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if (value == null)
        {
            writer.WriteNullValue();
        }
        else
        {
            var encodedString = WebEncoders.Base64UrlEncode(value);
            writer.WriteStringValue(encodedString);
        }
    }
}
