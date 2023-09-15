using System;

namespace WebAuthn.Net.Services.TimeProvider;

public interface ITimeProvider
{
    DateTimeOffset GetUtcDateTime();
}
