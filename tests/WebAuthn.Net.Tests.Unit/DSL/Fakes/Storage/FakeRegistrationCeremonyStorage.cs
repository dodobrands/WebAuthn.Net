using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Storage.RegistrationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.DSL.Fakes.Storage;

public class FakeRegistrationCeremonyStorage : IRegistrationCeremonyStorage<FakeWebAuthnContext>
{
    private readonly object _locker = new();
    private readonly Dictionary<string, RegistrationCeremonyParameters> _registrationCeremonies = new();

    public Task<string> SaveAsync(
        FakeWebAuthnContext context,
        RegistrationCeremonyParameters registrationCeremonyParameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var id = Guid.NewGuid().ToString("N");
        lock (_locker)
        {
            _registrationCeremonies[id] = registrationCeremonyParameters;
        }

        return Task.FromResult(id);
    }

    public Task<RegistrationCeremonyParameters?> FindAsync(
        FakeWebAuthnContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RegistrationCeremonyParameters? result = null;
        lock (_locker)
        {
            if (_registrationCeremonies.TryGetValue(registrationCeremonyId, out var value))
            {
                result = value;
            }
        }

        return Task.FromResult(result);
    }

    public Task RemoveAsync(
        FakeWebAuthnContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        bool removed;
        lock (_locker)
        {
            removed = _registrationCeremonies.Remove(registrationCeremonyId);
        }

        return Task.FromResult(removed);
    }

    public void ReplaceChallengeForRegistrationCeremonyOptions(
        string registrationCeremonyId,
        byte[] challenge)
    {
        lock (_locker)
        {
            if (_registrationCeremonies.TryGetValue(registrationCeremonyId, out var existingCeremony))
            {
                var options = existingCeremony.Options;
                var newOptions = new PublicKeyCredentialCreationOptions(
                    options.Rp,
                    options.User,
                    challenge,
                    options.PubKeyCredParams,
                    options.Timeout,
                    options.ExcludeCredentials,
                    options.AuthenticatorSelection,
                    options.Hints,
                    options.Attestation,
                    options.AttestationFormats,
                    options.Extensions);
                var newCeremony = new RegistrationCeremonyParameters(
                    newOptions,
                    existingCeremony.ExpectedRp,
                    existingCeremony.CreatedAt,
                    existingCeremony.ExpiresAt);
                _registrationCeremonies[registrationCeremonyId] = newCeremony;
            }
        }
    }
}
