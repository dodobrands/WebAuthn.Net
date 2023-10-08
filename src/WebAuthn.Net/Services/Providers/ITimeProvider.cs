using System;

namespace WebAuthn.Net.Services.Providers;

public interface ITimeProvider
{
    DateTimeOffset GetRoundUtcDateTime();
    DateTimeOffset GetPreciseUtcDateTime();
}
