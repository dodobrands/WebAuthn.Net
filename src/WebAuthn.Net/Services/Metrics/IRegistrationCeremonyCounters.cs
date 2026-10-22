using WebAuthn.Net.Models.Protocol.Enums;
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

    /// <summary>
    ///     Increments the counter of the anomalies found while verifying an attestation statement during the registration ceremony:
    ///     deviations from the specifications that the library tolerates (the attestation statement is still accepted) and values unknown to the library
    ///     that cause the attestation statement to be rejected (for example, a TPM manufacturer that is not in the library's copy of the TCG TPM Vendor ID Registry).
    /// </summary>
    /// <param name="fmt">The <a href="https://www.w3.org/TR/webauthn-3/#attestation-statement-format-identifier">attestation statement format identifier</a> (for example, <c>tpm</c>).</param>
    /// <param name="anomaly">The anomaly, one of a bounded set of values defined by the verifier of the attestation statement format (for example, <c>pubarea.reserved_bit_3</c>).</param>
    /// <param name="tolerated"><see langword="true" /> if the attestation statement was accepted despite the anomaly, <see langword="false" /> if it was rejected because of it.</param>
    void IncrementAttestationStatementAnomaly(string fmt, string anomaly, bool tolerated);

    /// <summary>
    ///     Increments the counter of the anomalies found while decoding the response of the registration ceremony (the <a href="https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson">RegistrationResponseJSON</a> sent by the client):
    ///     deviations from the specifications and values unknown to the library that the library tolerates (the response is still accepted) or that cause the response to be rejected
    ///     (for example, a transport that is not a member of <see cref="AuthenticatorTransport" />).
    /// </summary>
    /// <param name="anomaly">The anomaly, one of a bounded set of values defined by the decoder of the response (for example, <c>transports.unknown_value</c>).</param>
    /// <param name="tolerated"><see langword="true" /> if the response was accepted despite the anomaly, <see langword="false" /> if it was rejected because of it.</param>
    void IncrementResponseAnomaly(string anomaly, bool tolerated);
}
