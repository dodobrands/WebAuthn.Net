using WebAuthn.Net.Services.RegistrationCeremony;

namespace WebAuthn.Net.Services.Metrics;

/// <summary>
///     Counters for registration ceremony metrics.
/// </summary>
public interface IRegistrationCeremonyCounters
{
    /// <summary>
    ///     Increments the counter of <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.BeginCeremonyAsync" /> calls.
    /// </summary>
    void IncrementBeginCeremonyStart();

    /// <summary>
    ///     Increments the counter of <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.BeginCeremonyAsync" /> completions.
    /// </summary>
    /// <param name="successful">Flag indicating whether the completion was successful.</param>
    void IncrementBeginCeremonyEnd(bool successful);

    /// <summary>
    ///     Increments the counter of <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.CompleteCeremonyAsync" /> calls.
    /// </summary>
    void IncrementCompleteCeremonyStart();

    /// <summary>
    ///     Increments the counter of <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.CompleteCeremonyAsync" /> completions.
    /// </summary>
    /// <param name="successful">Flag indicating whether the completion was successful.</param>
    void IncrementCompleteCeremonyEnd(bool successful);
}
