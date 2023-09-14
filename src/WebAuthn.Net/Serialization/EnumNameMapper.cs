using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Text.Json;

namespace WebAuthn.Net.Serialization;

static class EnumNameMapper<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>
    where TEnum : struct, Enum
{
    private static readonly Dictionary<TEnum, string> ValueToNames = GetIdToNameMap().ToDictionary(i => i.value, i => i.name);
    private static readonly Dictionary<string, TEnum> NamesToValues = Invert(ValueToNames);

    private static Dictionary<string, TEnum> Invert(Dictionary<TEnum, string> map)
    {
        var result = new Dictionary<string, TEnum>(map.Count, StringComparer.OrdinalIgnoreCase);

        foreach (var item in map)
        {
            result[item.Value] = item.Key;
        }

        return result;
    }

    public static bool TryGetValue(string name, out TEnum value)
    {
        return NamesToValues.TryGetValue(name, out value);
    }

    public static string GetName(TEnum value)
    {
        return ValueToNames[value];
    }

    private static IEnumerable<(TEnum value, string name)> GetIdToNameMap()
    {
        foreach (var field in typeof(TEnum).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            var description = field.GetCustomAttribute<EnumMemberAttribute>(false);
            if (description is null)
            {
                throw new JsonException($"EnumMemberAttribute is required for enum members. Type: {typeof(TEnum).FullName} Field: {field.Name}");
            }

            if (description.Value is null)
            {
                throw new JsonException("EnumMemberAttribute must specify json property name.");
            }

            var value = (TEnum) (field.GetValue(null)!);
            var name = description.Value;

            yield return (value, name);
        }
    }
}
