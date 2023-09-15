using System;

namespace WebAuthn.Net.Extensions;

/// <summary>
///     Extension methods for arrays.
/// </summary>
public static class ArrayExtensions
{
    /// <summary>
    ///     Creates a copy of the specified array.
    /// </summary>
    /// <param name="source">The source array that needs to be copied.</param>
    /// <typeparam name="T">The type of objects in the array.</typeparam>
    /// <returns>A copy of the passed byte array.</returns>
    /// <exception cref="ArgumentNullException">If the <paramref name="source" /> parameter is <see langword="null" />.</exception>
    public static T[] CreateCopy<T>(this T[] source)
    {
        ArgumentNullException.ThrowIfNull(source);
        var copy = new T[source.Length];
        Array.Copy(source, copy, copy.Length);
        return copy;
    }
}
