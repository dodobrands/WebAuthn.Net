using System;

namespace WebAuthn.Net.Services.Providers;

/// <summary>
///     Current time provider.
/// </summary>
public interface ITimeProvider
{
    /// <summary>
    ///     Returns the current date and time in UTC, rounded to the second.
    /// </summary>
    /// <returns>The current date and time in UTC, rounded to the second.</returns>
    DateTimeOffset GetRoundUtcDateTime();

    /// <summary>
    ///     Returns the current date and time in UTC without any rounding.
    /// </summary>
    /// <returns>The current date and time in UTC without any rounding.</returns>
    DateTimeOffset GetPreciseUtcDateTime();
}
