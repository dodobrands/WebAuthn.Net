using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using WebAuthn.Net.Services.Serialization;

namespace WebAuthn.Net.Serialization.Json;

/// <summary>
///     Converter for overriding enum value serialization.
///     The value of a specific <typeparamref name="TEnum" /> member will be taken from the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute.
///     All <typeparamref name="TEnum" /> values must be annotated with this attribute.
/// </summary>
/// <typeparam name="TEnum">The <see cref="Enum" /> type for which serialization needs to be overridden.</typeparam>
public sealed class EnumMemberAttributeValueConverter<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum> : JsonConverter<TEnum>
    where TEnum : struct, Enum
{
    private static readonly EnumMemberAttributeMapper<TEnum> Mapper = new();

    /// <inheritdoc />
    public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var enumText = reader.GetString();

        if (enumText is null)
        {
            throw new JsonException("Expected enum name");
        }

        if (Mapper.TryGetEnumFromString(enumText, out var value))
        {
            return value;
        }

        throw new JsonException($"Invalid enum value = {enumText}");
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        if (!Mapper.TryGetStringFromEnum(value, out var enumText))
        {
            throw new JsonException($"Can't get string representation for '{value}' enum value");
        }

        writer.WriteStringValue(enumText);
    }
}
