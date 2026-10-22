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

    /// <summary>
    ///     Increments the counter of the anomalies found while verifying the response of the authentication ceremony (the <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationresponsejson">AuthenticationResponseJSON</a> sent by the client):
    ///     signals that the Relying Party policy either tolerates (the response is still accepted) or treats as a reason to reject the response
    ///     (for example, a signature counter that did not increase, which may mean that the authenticator is cloned).
    /// </summary>
    /// <param name="anomaly">The anomaly, one of a bounded set of values defined by the authentication ceremony service (for example, <c>sign_count.not_increased</c>).</param>
    /// <param name="tolerated"><see langword="true" /> if the response was accepted despite the anomaly, <see langword="false" /> if it was rejected because of it.</param>
    void IncrementResponseAnomaly(string anomaly, bool tolerated);
}
