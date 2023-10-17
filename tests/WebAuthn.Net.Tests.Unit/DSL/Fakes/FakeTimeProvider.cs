using System;
using WebAuthn.Net.Services.Providers;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeTimeProvider : ITimeProvider
{
    private DateTimeOffset _precise;
    private DateTimeOffset _round;

    public FakeTimeProvider(DateTimeOffset date)
    {
        _precise = DateTimeOffset.FromUnixTimeMilliseconds(date.ToUnixTimeMilliseconds());
        _round = DateTimeOffset.FromUnixTimeSeconds(date.ToUnixTimeSeconds());
    }

    public DateTimeOffset GetRoundUtcDateTime()
    {
        return _round;
    }

    public DateTimeOffset GetPreciseUtcDateTime()
    {
        return _precise;
    }

    public void Change(DateTimeOffset newDate)
    {
        _precise = DateTimeOffset.FromUnixTimeMilliseconds(newDate.ToUnixTimeMilliseconds());
        _round = DateTimeOffset.FromUnixTimeSeconds(newDate.ToUnixTimeSeconds());
    }
}
