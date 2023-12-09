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
