using System;
using System.Globalization;

namespace WebAuthn.Net.Services.Static;

/// <summary>
///     A static utility for preparing values received from a client (and therefore controlled by an attacker) for logging.
/// </summary>
public static class LogValue
{
    /// <summary>
    ///     The maximum number of characters of a value that are written to the log by default.
    /// </summary>
    public const int DefaultMaxLength = 256;

    /// <summary>
    ///     Makes a value received from a client safe to write to the log: control, format and line separator characters are replaced with '?',
    ///     so the value can't forge or split log records in plain-text sinks, and the value is truncated, so it can't flood the log.
    /// </summary>
    /// <param name="value">The value received from a client.</param>
    /// <param name="maxLength">The maximum number of characters of the value that are kept.</param>
    /// <returns>The value that can be written to the log. An empty string if <paramref name="value" /> is <see langword="null" />.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength" /> is negative.</exception>
    public static string Sanitize(string? value, int maxLength = DefaultMaxLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxLength);
        if (value is null)
        {
            return string.Empty;
        }

        var truncated = value.Length > maxLength;
        var length = truncated ? maxLength : value.Length;
        return string.Create(truncated ? length + 3 : length, (value, length, truncated), static (span, state) =>
        {
            for (var i = 0; i < state.length; i++)
            {
                var character = state.value[i];
                span[i] = IsUnsafe(character) ? '?' : character;
            }

            if (state.truncated)
            {
                span[state.length..].Fill('.');
            }
        });
    }

    private static bool IsUnsafe(char character)
    {
        return CharUnicodeInfo.GetUnicodeCategory(character)
            is UnicodeCategory.Control
            or UnicodeCategory.Format
            or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator;
    }
}
