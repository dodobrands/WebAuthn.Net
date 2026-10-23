using System;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using WebAuthn.Net.Services.Metrics.Implementation.Constants;
using WebAuthn.Net.Services.RegistrationCeremony;

namespace WebAuthn.Net.Services.Metrics.Implementation;

/// <summary>
///     Default implementation of <see cref="IRegistrationCeremonyCounters" />.
/// </summary>
public class DefaultRegistrationCeremonyCounters : IRegistrationCeremonyCounters, IDisposable
{
    /// <summary>
    ///     Constructs <see cref="DefaultRegistrationCeremonyCounters" />.
    /// </summary>
    public DefaultRegistrationCeremonyCounters()
    {
        Meter = new(Meters.RegistrationCeremonyMeterName);
        BeginCeremonyStartCounter = Meter.CreateCounter<long>(
            "webauthn.reg.begin.start",
            null,
            "The number of calls to the method responsible for the beginning of the registration ceremony (IRegistrationCeremonyService.BeginCeremonyAsync)");
        BeginCeremonyEndCounter = Meter.CreateCounter<long>(
            "webauthn.reg.begin.end",
            null,
            "The number of completions of the method responsible for the beginning of the registration ceremony (IRegistrationCeremonyService.BeginCeremonyAsync)"
        );
        CompleteCeremonyStartCounter = Meter.CreateCounter<long>(
            "webauthn.reg.complete.start",
            null,
            "The number of calls to the method responsible for the completion of the registration ceremony (IRegistrationCeremonyService.CompleteCeremonyAsync)");
        CompleteCeremonyEndCounter = Meter.CreateCounter<long>(
            "webauthn.reg.complete.end",
            null,
            "The number of completions of the method responsible for the completion of the registration ceremony (IRegistrationCeremonyService.CompleteCeremonyAsync))");
        AttestationStatementAnomaliesCounter = Meter.CreateCounter<long>(
            "webauthn.reg.attestation.anomalies",
            null,
            "The number of anomalies found while verifying attestation statements: deviations from the specifications that were tolerated, and values unknown to the library or inconsistent with the attestation that caused the attestation statement to be rejected");
        ResponseAnomaliesCounter = Meter.CreateCounter<long>(
            "webauthn.reg.response.anomalies",
            null,
            "The number of anomalies found while decoding the responses of the registration ceremony: deviations from the specifications and values unknown to the library, either tolerated or causing the response to be rejected");
    }

    /// <summary>
    ///     <see cref="Meter" /> responsible for creating and tracking Instruments of the registration ceremony.
    /// </summary>
    protected Meter Meter { get; }

    /// <summary>
    ///     Counter for calls to the method responsible for the start of the registration ceremony <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.BeginCeremonyAsync" />.
    /// </summary>
    protected Counter<long> BeginCeremonyStartCounter { get; }

    /// <summary>
    ///     The completion counter of the method responsible for the start of the registration ceremony <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.BeginCeremonyAsync" />.
    /// </summary>
    protected Counter<long> BeginCeremonyEndCounter { get; }

    /// <summary>
    ///     Counter for calls to the method responsible for the completion of the registration ceremony <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.CompleteCeremonyAsync" />.
    /// </summary>
    protected Counter<long> CompleteCeremonyStartCounter { get; }

    /// <summary>
    ///     The completion counter of the method responsible for the completion of the registration ceremony <see cref="IRegistrationCeremonyService" />.<see cref="IRegistrationCeremonyService.CompleteCeremonyAsync" />.
    /// </summary>
    protected Counter<long> CompleteCeremonyEndCounter { get; }

    /// <summary>
    ///     Counter for the anomalies found while verifying attestation statements during the registration ceremony.
    /// </summary>
    protected Counter<long> AttestationStatementAnomaliesCounter { get; }

    /// <summary>
    ///     Counter for the anomalies found while decoding the responses of the registration ceremony.
    /// </summary>
    protected Counter<long> ResponseAnomaliesCounter { get; }

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public virtual void IncrementBeginCeremonyStart()
    {
        BeginCeremonyStartCounter.Add(1);
    }

    /// <inheritdoc />
    public virtual void IncrementBeginCeremonyEnd(bool successful)
    {
        var status = successful
            ? TagValues.StatusSuccess
            : TagValues.StatusFail;
        BeginCeremonyEndCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Status, status)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementCompleteCeremonyStart()
    {
        CompleteCeremonyStartCounter.Add(1);
    }

    /// <inheritdoc />
    public virtual void IncrementCompleteCeremonyEnd(bool successful)
    {
        var status = successful
            ? TagValues.StatusSuccess
            : TagValues.StatusFail;
        CompleteCeremonyEndCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Status, status)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementAttestationStatementAnomaly(string fmt, string anomaly, bool tolerated)
    {
        var outcome = tolerated
            ? TagValues.OutcomeTolerated
            : TagValues.OutcomeRejected;
        AttestationStatementAnomaliesCounter.Add(
            1L,
            new TagList
            {
                new(Tags.AttestationStatementFormat, fmt),
                new(Tags.Anomaly, anomaly),
                new(Tags.Outcome, outcome)
            });
    }

    /// <inheritdoc />
    public virtual void IncrementResponseAnomaly(string anomaly, bool tolerated)
    {
        var outcome = tolerated
            ? TagValues.OutcomeTolerated
            : TagValues.OutcomeRejected;
        ResponseAnomaliesCounter.Add(
            1L,
            new TagList
            {
                new(Tags.Anomaly, anomaly),
                new(Tags.Outcome, outcome)
            });
    }

    /// <summary>
    ///     Releases all resources currently used by this <see cref="DefaultRegistrationCeremonyCounters" /> instance.
    /// </summary>
    /// <param name="disposing"><see langword="true" /> if this method is being invoked by the <see cref="Dispose()" /> method, otherwise <see langword="false" />.</param>
    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            Meter.Dispose();
        }
    }
}
