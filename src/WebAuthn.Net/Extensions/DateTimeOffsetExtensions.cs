using System;

namespace WebAuthn.Net.Extensions;

public static class DateTimeOffsetExtensions
{
    public static DateTimeOffset ComputeExpiresAtUtc(this DateTimeOffset value, uint timeout)
    {
        var expiresAtMilliseconds = value.ToUnixTimeMilliseconds() + timeout;
        return DateTimeOffset.FromUnixTimeMilliseconds(expiresAtMilliseconds);
    }
}
