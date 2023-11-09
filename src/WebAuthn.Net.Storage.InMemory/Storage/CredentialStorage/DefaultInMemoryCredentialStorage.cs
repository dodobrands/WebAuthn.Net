using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.InMemory.Models;
using WebAuthn.Net.Storage.InMemory.Storage.CredentialStorage.Models;

namespace WebAuthn.Net.Storage.InMemory.Storage.CredentialStorage;

public class DefaultInMemoryCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : DefaultInMemoryContext
{
    private readonly List<InMemoryUserCredentialRecord> _credentials = new();
    private readonly object _locker = new();

    public DefaultInMemoryCredentialStorage(ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        TimeProvider = timeProvider;
    }

    protected ITimeProvider TimeProvider { get; }

    public virtual Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryUserCredentialRecord[] records;
        lock (_locker)
        {
            records = _credentials
                .Where(x => x.RpId == rpId && x.UserHandle.AsSpan().SequenceEqual(userHandle.AsSpan()))
                .OrderByDescending(x => x.CreatedAtUnixTime)
                .ToArray();
        }

        var descriptors = new PublicKeyCredentialDescriptor[records.Length];
        for (var i = 0; i < records.Length; i++)
        {
            var record = records[i];
            if (!record.TryMapToDescriptor(out var descriptor))
            {
                throw new InvalidOperationException($"Failed to convert data into {nameof(PublicKeyCredentialDescriptor)}");
            }

            descriptors[i] = descriptor;
        }

        return Task.FromResult(descriptors);
    }

    public virtual Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        InMemoryUserCredentialRecord? record;
        lock (_locker)
        {
            record = _credentials.FirstOrDefault(x =>
                x.RpId == rpId
                && x.UserHandle.AsSpan().SequenceEqual(userHandle.AsSpan())
                && x.CredentialId.AsSpan().SequenceEqual(credentialId.AsSpan()));
        }

        if (record is null)
        {
            return Task.FromResult<UserCredentialRecord?>(null);
        }

        if (!record.TryMapToUserCredentialRecord(out var result))
        {
            throw new InvalidOperationException($"Failed to convert data into {nameof(UserCredentialRecord)}");
        }

        return Task.FromResult<UserCredentialRecord?>(result);
    }

    public virtual Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_locker)
        {
            var alreadyExists = _credentials.Any(x =>
                x.RpId == credential.RpId
                && x.CredentialId.AsSpan().SequenceEqual(credential.CredentialRecord.Id.AsSpan()));
            if (alreadyExists)
            {
                return Task.FromResult(false);
            }

            _credentials.Add(new(credential, TimeProvider.GetPreciseUtcDateTime()));
        }

        return Task.FromResult(true);
    }

    public virtual Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_locker)
        {
            var itemToUpdateExists = false;
            var recordsToRemove = _credentials.Where(x =>
                    x.RpId == credential.RpId
                    && x.UserHandle.AsSpan().SequenceEqual(credential.UserHandle)
                    && x.CredentialId.AsSpan().SequenceEqual(credential.CredentialRecord.Id.AsSpan()))
                .ToArray();

            foreach (var recordToRemove in recordsToRemove)
            {
                _credentials.Remove(recordToRemove);
                itemToUpdateExists = true;
            }

            if (!itemToUpdateExists)
            {
                return Task.FromResult(false);
            }

            _credentials.Add(new(credential, TimeProvider.GetPreciseUtcDateTime()));
        }

        return Task.FromResult(true);
    }
}
