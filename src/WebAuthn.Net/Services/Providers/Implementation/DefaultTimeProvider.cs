using System;

namespace WebAuthn.Net.Services.Providers.Implementation;

/// <summary>
///     Default implementation of <see cref="ITimeProvider" />.
/// </summary>
public class DefaultTimeProvider : ITimeProvider
{
    /// <inheritdoc />
    public virtual DateTimeOffset GetRoundUtcDateTime()
    {
        return DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    /// <inheritdoc />
    public virtual DateTimeOffset GetPreciseUtcDateTime()
    {
        return DateTimeOffset.UtcNow;
    }
}
