using System;

namespace WebAuthn.Net.Services.TimeProvider.Implementation;

public class DefaultTimeProvider : ITimeProvider
{
    public DateTimeOffset GetRoundUtcDateTime()
    {
        return DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    public DateTimeOffset GetPreciseUtcDateTime()
    {
        return DateTimeOffset.UtcNow;
    }
}
