using System;

namespace WebAuthn.Net.Services.TimeProvider.Implementation;

public class DefaultTimeProvider : ITimeProvider
{
    public DateTimeOffset GetUtcDateTime()
    {
        return DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }
}
