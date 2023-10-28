using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.DSL.Fakes.Storage;

public class FakeAuthenticationCeremonyStorage : IAuthenticationCeremonyStorage<FakeWebAuthnContext>
{
    private readonly Dictionary<string, AuthenticationCeremonyParameters> _authenticationCeremonies = new();
    private readonly object _locker = new();

    public Task<string> SaveAsync(
        FakeWebAuthnContext context,
        AuthenticationCeremonyParameters authenticationCeremony,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var id = Guid.NewGuid().ToString("N");
        lock (_locker)
        {
            _authenticationCeremonies[id] = authenticationCeremony;
        }

        return Task.FromResult(id);
    }

    public Task<AuthenticationCeremonyParameters?> FindAsync(
        FakeWebAuthnContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        AuthenticationCeremonyParameters? result = null;
        lock (_locker)
        {
            if (_authenticationCeremonies.TryGetValue(authenticationCeremonyId, out var value))
            {
                result = value;
            }
        }

        return Task.FromResult(result);
    }

    public Task RemoveAsync(
        FakeWebAuthnContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        bool removed;
        lock (_locker)
        {
            removed = _authenticationCeremonies.Remove(authenticationCeremonyId);
        }

        return Task.FromResult(removed);
    }
}
