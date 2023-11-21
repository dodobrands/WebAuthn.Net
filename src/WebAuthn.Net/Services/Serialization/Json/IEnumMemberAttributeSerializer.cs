using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.Serialization.Json;

/// <summary>
///     Mapper for converting <typeparamref name="TEnum" /> values to strings and vice versa.
///     The string value of a specific <typeparamref name="TEnum" /> member will be taken from the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute.
///     All <typeparamref name="TEnum" /> values must be annotated with the <see cref="System.Runtime.Serialization.EnumMemberAttribute" /> attribute.
/// </summary>
/// <typeparam name="TEnum"><see cref="Enum" /> type for which mapping is required.</typeparam>
public interface IEnumMemberAttributeSerializer<TEnum>
    where TEnum : struct, Enum
{
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
    bool TryDeserialize(string key, [NotNullWhen(true)] out TEnum? value);

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
    bool TrySerialize(TEnum key, [NotNullWhen(true)] out string? value);
}
