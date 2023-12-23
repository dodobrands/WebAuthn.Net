using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Demo.Mvc.Extensions;

public static class EnumExtensions
{
    public static T? RemapUnsetValue<T>(this string value) where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Equals("unset", StringComparison.Ordinal))
        {
            return null;
        }

        var serializer = new DefaultEnumMemberAttributeSerializer<T>();
        if (serializer.TryDeserialize(value, out var enumValue))
        {
            return enumValue;
        }

        return null;
    }
}
