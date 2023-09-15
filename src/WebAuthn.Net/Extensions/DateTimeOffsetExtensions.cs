using System;

namespace WebAuthn.Net.Extensions;

public static class DateTimeOffsetExtensions
{
    public static DateTimeOffset? ComputeExpiresAtUtc(this DateTimeOffset value, uint? timeout)
    {
        if (!timeout.HasValue)
        {
            return null;
        }

        var expiresAtMilliseconds = value.ToUnixTimeMilliseconds() + timeout.Value;
        return DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMilliseconds);
    }
}
