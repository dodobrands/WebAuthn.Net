using System;
using System.Collections.Generic;

namespace WebAuthn.Net.Extensions;

public static class EnumExtensions
{
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
