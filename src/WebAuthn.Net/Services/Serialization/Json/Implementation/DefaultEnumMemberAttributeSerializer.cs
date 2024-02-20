using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Services.Serialization.Json.Implementation;

/// <summary>
///     Default implementation of <see cref="IEnumMemberAttributeSerializer{TEnum}" />.
/// </summary>
/// <typeparam name="TEnum"><see cref="Enum" /> type for which mapping is required.</typeparam>
public class DefaultEnumMemberAttributeSerializer<TEnum> : IEnumMemberAttributeSerializer<TEnum>
    where TEnum : struct, Enum
{
    private readonly HashSet<TEnum> _allEnumValues;
    private readonly Dictionary<string, TEnum> _namesToValues;
    private readonly Dictionary<TEnum, string> _valuesToNames;

    /// <summary>
    ///     Constructs <see cref="DefaultEnumMemberAttributeSerializer{TEnum}" />.
    /// </summary>
    public DefaultEnumMemberAttributeSerializer()
    {
        _namesToValues = GetSerializedValueToEnumMap();
        _valuesToNames = _namesToValues.ToDictionary(static x => x.Value, static x => x.Key);
        _allEnumValues = Enum.GetValues<TEnum>().ToHashSet();
    }

    /// <inheritdoc />
    public virtual bool TryDeserialize(string key, [NotNullWhen(true)] out TEnum? value)
    {
        if (_namesToValues.TryGetValue(key, out var result))
        {
            value = result;
            return true;
        }

        value = null;
        return false;
    }

    /// <inheritdoc />
    public virtual bool TrySerialize(TEnum key, [NotNullWhen(true)] out string? value)
    {
        if (!_allEnumValues.Contains(key))
        {
            value = null;
            return false;
        }

        return _valuesToNames.TryGetValue(key, out value);
    }

    private static Dictionary<string, TEnum> GetSerializedValueToEnumMap()
    {
        var enumType = typeof(TEnum);
        var enumValues = Enum.GetValues<TEnum>();
        var result = new Dictionary<string, TEnum>(enumValues.Length, StringComparer.Ordinal);
        foreach (var enumValue in enumValues)
        {
            var systemName = Enum.GetName(enumValue);
            if (systemName is null)
            {
                throw new InvalidOperationException($"Can't get {systemName} value of {enumType.FullName} type");
            }

            var enumMemberAttribute = enumType.GetField(systemName)?.GetCustomAttributes<EnumMemberAttribute>(false).Single();
            if (enumMemberAttribute is null)
            {
                throw new InvalidOperationException($"Can't get [EnumMember] attribute for {systemName} value of {enumType.FullName} type");
            }

            var name = enumMemberAttribute.Value;
            if (string.IsNullOrEmpty(name))
            {
                throw new InvalidOperationException($"Value of [EnumMember(Value = \"\")] attribute for {systemName} value of {enumType.FullName} type can't be null or empty string");
            }

            if (!result.TryAdd(name, enumValue))
            {
                throw new InvalidOperationException($"Value of [EnumMember(Value = \"SomeValue\")] attribute for {systemName} value of {enumType.FullName} type is duplicates with some other value");
            }
        }

        return result;
    }
}
