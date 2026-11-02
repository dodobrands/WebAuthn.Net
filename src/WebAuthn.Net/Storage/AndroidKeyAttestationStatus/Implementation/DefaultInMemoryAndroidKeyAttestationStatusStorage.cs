using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;

namespace WebAuthn.Net.Storage.AndroidKeyAttestationStatus.Implementation;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatusStorage" /> that keeps the status list in memory.
/// </summary>
/// <remarks>
///     The status list is lost when the application stops, so after every start it is loaded again: embedded in the application, if it is configured, and downloaded.
/// </remarks>
public class DefaultInMemoryAndroidKeyAttestationStatusStorage : IAndroidKeyAttestationStatusStorage
{
    private volatile AndroidKeyAttestationStatusList? _statusList;

    /// <inheritdoc />
    public virtual Task<AndroidKeyAttestationStatusList?> GetAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_statusList);
    }

    /// <inheritdoc />
    public virtual Task UpsertAsync(AndroidKeyAttestationStatusList statusList, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(statusList);
        cancellationToken.ThrowIfCancellationRequested();
        _statusList = statusList;
        return Task.CompletedTask;
    }
}
