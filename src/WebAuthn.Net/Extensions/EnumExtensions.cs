using System;
using System.Collections.Generic;

namespace WebAuthn.Net.Extensions;

/// <summary>
///     Extension methods for enums.
/// </summary>
public static class EnumExtensions
{
    /// <summary>
    ///     Converts a <typeparamref name="TEnum" /> value composed of a set of bitwise flags into a <see cref="IReadOnlySet{TEnum}" /> of individual <typeparamref name="TEnum" /> values.
    /// </summary>
    /// <param name="value">The <typeparamref name="TEnum" /> value composed of a set of bitwise flags.</param>
    /// <typeparam name="TEnum">The type of the <see cref="Enum" /> for which the operation is performed.</typeparam>
    /// <returns><see cref="IReadOnlySet{TEnum}" /> containing individual values of <typeparamref name="TEnum" />.</returns>
    public static IReadOnlySet<TEnum> FlagsToSet<TEnum>(this TEnum value) where TEnum : struct, Enum
    {
        var set = new HashSet<TEnum>();
        foreach (var element in Enum.GetValues<TEnum>())
        {
            if (value.HasFlag(element))
            {
                set.Add(element);
            }
        }

        return set;
    }
}
