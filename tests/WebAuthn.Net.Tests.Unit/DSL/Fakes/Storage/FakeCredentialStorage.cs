using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.DSL.Fakes.Storage;

public class FakeCredentialStorage : ICredentialStorage<FakeWebAuthnContext>
{
    private readonly List<UserCredentialRecord> _credentials = new();
    private readonly object _locker = new();

    public Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        FakeWebAuthnContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var foundDescriptors = new List<PublicKeyCredentialDescriptor>();
        lock (_locker)
        {
            foreach (var existingCredential in _credentials)
            {
                if (existingCredential.RpId == rpId && existingCredential.UserHandle.AsSpan().SequenceEqual(userHandle.AsSpan()))
                {
                    var descriptor = new PublicKeyCredentialDescriptor(
                        existingCredential.CredentialRecord.Type,
                        existingCredential.CredentialRecord.Id,
                        existingCredential.CredentialRecord.Transports);
                    foundDescriptors.Add(descriptor);
                }
            }
        }

        if (foundDescriptors.Count > 0)
        {
            return Task.FromResult(foundDescriptors.ToArray());
        }

        return Task.FromResult(Array.Empty<PublicKeyCredentialDescriptor>());
    }

    public Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        FakeWebAuthnContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        UserCredentialRecord? result = null;
        lock (_locker)
        {
            foreach (var existingCredential in _credentials)
            {
                if (existingCredential.RpId == rpId
                    && existingCredential.UserHandle.AsSpan().SequenceEqual(userHandle.AsSpan())
                    && existingCredential.CredentialRecord.Id.AsSpan().SequenceEqual(credentialId.AsSpan()))
                {
                    result = existingCredential;
                    break;
                }
            }
        }

        return Task.FromResult(result);
    }

    public Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        FakeWebAuthnContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();

        var saved = false;
        lock (_locker)
        {
            var alreadyUsed = false;
            foreach (var existingCredential in _credentials)
            {
                if (existingCredential.RpId == credential.RpId
                    && existingCredential.CredentialRecord.Id.AsSpan().SequenceEqual(credential.CredentialRecord.Id.AsSpan()))
                {
                    alreadyUsed = true;
                    break;
                }
            }

            if (!alreadyUsed)
            {
                _credentials.Add(credential);
                saved = true;
            }
        }

        return Task.FromResult(saved);
    }

    public Task<bool> UpdateCredentialAsync(
        FakeWebAuthnContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(credential);
        cancellationToken.ThrowIfCancellationRequested();

        var updated = false;
        lock (_locker)
        {
            UserCredentialRecord? credentialToUpdate = null;
            foreach (var existingCredential in _credentials)
            {
                if (existingCredential.RpId == credential.RpId
                    && existingCredential.UserHandle.AsSpan().SequenceEqual(credential.UserHandle.AsSpan())
                    && existingCredential.CredentialRecord.Id.AsSpan().SequenceEqual(credential.CredentialRecord.Id.AsSpan()))
                {
                    credentialToUpdate = existingCredential;
                    break;
                }
            }

            if (credentialToUpdate is not null)
            {
                _credentials.Remove(credentialToUpdate);
                _credentials.Add(credential);
                updated = true;
            }
        }

        return Task.FromResult(updated);
    }
}
