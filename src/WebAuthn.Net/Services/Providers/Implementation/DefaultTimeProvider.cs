using System;

namespace WebAuthn.Net.Services.Providers.Implementation;

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
