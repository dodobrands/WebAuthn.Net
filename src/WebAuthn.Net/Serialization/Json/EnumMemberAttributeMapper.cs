using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;

namespace WebAuthn.Net.Serialization.Json;

/// <summary>
///     Mapper for converting <typeparamref name="TEnum" /> values to strings and vice versa.
///     The string value of a specific <typeparamref name="TEnum" /> member will be taken from the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute.
///     All <typeparamref name="TEnum" /> values must be annotated with the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute.
/// </summary>
/// <typeparam name="TEnum">An <see cref="Enum" /> for which an instance of this mapper is required.</typeparam>
public class EnumMemberAttributeMapper<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields)] TEnum>
    where TEnum : struct, Enum
{
    private readonly Dictionary<string, TEnum> _namesToValues;
    private readonly Dictionary<TEnum, string> _valuesToNames;

    /// <summary>
    ///     Constructs <see cref="EnumMemberAttributeMapper{TEnum}" />.
    /// </summary>
    public EnumMemberAttributeMapper()
    {
        _namesToValues = GetSerializedValueToEnumMap();
        _valuesToNames = _namesToValues.ToDictionary(static x => x.Value, static x => x.Key);
    }

    /// <summary>
    ///     Attempting to retrieve the <typeparamref name="TEnum" /> value from a string specified as
    ///     the <see cref="System.Runtime.Serialization.EnumMemberAttribute.Value" /> for one of the <typeparamref name="TEnum" /> members,
    ///     annotated with the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute.
    /// </summary>
    /// <param name="key">
    ///     The string specified as the <see cref="System.Runtime.Serialization.EnumMemberAttribute.Value" />
    ///     for the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute on one of the <typeparamref name="TEnum" /> members.
    /// </param>
    /// <param name="value">
    ///     The <typeparamref name="TEnum" /> value that is annotated with the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute,
    ///     where the <see cref="System.Runtime.Serialization.EnumMemberAttribute.Value" /> is equal to the <paramref name="key" /> parameter.
    /// </param>
    /// <returns>If <see langword="true" /> is returned, the sought-after value will be contained in the <paramref name="value" /> parameter.</returns>
    public bool TryGetEnumFromString(string key, out TEnum value)
    {
        return _namesToValues.TryGetValue(key, out value);
    }

    /// <summary>
    ///     Attempting to retrieve the value of the string specified as the <see cref="System.Runtime.Serialization.EnumMemberAttribute.Value" />
    ///     for a <typeparamref name="TEnum" /> member, marked with the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute.
    /// </summary>
    /// <param name="key">The <typeparamref name="TEnum" /> member for which the value needs to be retrieved.</param>
    /// <param name="value">
    ///     The string specified in the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute
    ///     for the value passed in the <paramref name="key" /> parameter.
    /// </param>
    /// <returns>If <see langword="true" /> is returned, the sought-after value will be contained in the <paramref name="value" /> parameter.</returns>
    public bool TryGetStringFromEnum(TEnum key, [NotNullWhen(true)] out string? value)
    {
        if (!Enum.IsDefined(key))
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

            if (result.ContainsKey(name))
            {
                throw new InvalidOperationException($"Value of [EnumMember(Value = \"SomeValue\")] attribute for {systemName} value of {enumType.FullName} type is duplicates with some other value");
            }

            result[name] = enumValue;
        }

        return result;
    }
}
