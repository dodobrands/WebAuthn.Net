using WebAuthn.Net.Services.AuthenticationCeremony;

namespace WebAuthn.Net.Services.Metrics;

/// <summary>
///     Counters for authentication ceremony metrics.
/// </summary>
public interface IAuthenticationCeremonyCounters
{
    /// <summary>
    ///     Increments the counter of <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.BeginCeremonyAsync" /> calls.
    /// </summary>
    void IncrementBeginCeremonyStart();

    /// <summary>
    ///     Increments the counter of <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.BeginCeremonyAsync" /> completions.
    /// </summary>
    /// <param name="successful">Flag indicating whether the completion was successful.</param>
    void IncrementBeginCeremonyEnd(bool successful);

    /// <summary>
    ///     Increments the counter of <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.CompleteCeremonyAsync" /> calls.
    /// </summary>
    void IncrementCompleteCeremonyStart();

    /// <summary>
    ///     Increments the counter of <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.CompleteCeremonyAsync" /> completions.
    /// </summary>
    /// <param name="successful">Flag indicating whether the completion was successful.</param>
    void IncrementCompleteCeremonyEnd(bool successful);
}
