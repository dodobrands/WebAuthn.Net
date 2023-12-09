using System;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.Metrics.Implementation.Constants;

namespace WebAuthn.Net.Services.Metrics.Implementation;

/// <summary>
///     Default implementation of <see cref="IAuthenticationCeremonyCounters" />.
/// </summary>
public class DefaultAuthenticationCeremonyCounters : IAuthenticationCeremonyCounters, IDisposable
{
    /// <summary>
    ///     Constructs <see cref="DefaultAuthenticationCeremonyCounters" />.
    /// </summary>
    public DefaultAuthenticationCeremonyCounters()
    {
        Meter = new(Meters.AuthenticationCeremonyMeterName);
        BeginCeremonyStartCounter = Meter.CreateCounter<long>(
            "webauthn.authn.begin.start",
            null,
            "The number of calls to the method responsible for the beginning of the authentication ceremony (IAuthenticationCeremonyService.BeginCeremonyAsync)");
        BeginCeremonyEndCounter = Meter.CreateCounter<long>(
            "webauthn.authn.begin.end",
            null,
            "The number of completions of the method responsible for the beginning of the authentication ceremony (IAuthenticationCeremonyService.BeginCeremonyAsync)"
        );
        CompleteCeremonyStartCounter = Meter.CreateCounter<long>(
            "webauthn.authn.complete.start",
            null,
            "The number of calls to the method responsible for the completion of the authentication ceremony (IAuthenticationCeremonyService.CompleteCeremonyAsync)");
        CompleteCeremonyEndCounter = Meter.CreateCounter<long>(
            "webauthn.authn.complete.end",
            null,
            "The number of completions of the method responsible for the completion of the authentication ceremony (IAuthenticationCeremonyService.CompleteCeremonyAsync))");
    }

    /// <summary>
    ///     <see cref="Meter" /> responsible for creating and tracking Instruments of the authentication ceremony.
    /// </summary>
    protected Meter Meter { get; }

    /// <summary>
    ///     Counter for calls to the method responsible for the start of the authentication ceremony <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.BeginCeremonyAsync" />.
    /// </summary>
    protected Counter<long> BeginCeremonyStartCounter { get; }

    /// <summary>
    ///     The completion counter of the method responsible for the start of the authentication ceremony <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.BeginCeremonyAsync" />.
    /// </summary>
    protected Counter<long> BeginCeremonyEndCounter { get; }

    /// <summary>
    ///     Counter for calls to the method responsible for the completion of the authentication ceremony <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.CompleteCeremonyAsync" />.
    /// </summary>
    protected Counter<long> CompleteCeremonyStartCounter { get; }

    /// <summary>
    ///     The completion counter of the method responsible for the completion of the authentication ceremony <see cref="IAuthenticationCeremonyService" />.<see cref="IAuthenticationCeremonyService.CompleteCeremonyAsync" />.
    /// </summary>
    protected Counter<long> CompleteCeremonyEndCounter { get; }

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
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    ///     Releases all resources currently used by this <see cref="DefaultAuthenticationCeremonyCounters" /> instance.
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
