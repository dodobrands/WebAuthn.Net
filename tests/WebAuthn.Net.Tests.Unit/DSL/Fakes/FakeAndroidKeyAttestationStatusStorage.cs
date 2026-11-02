using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;
using WebAuthn.Net.Storage.AndroidKeyAttestationStatus;

namespace WebAuthn.Net.DSL.Fakes;

/// <summary>
///     A storage of the status list of the Android attestation keys that starts with a given status list (by default, an empty one, so that no certificate is revoked).
/// </summary>
public class FakeAndroidKeyAttestationStatusStorage : IAndroidKeyAttestationStatusStorage
{
    public FakeAndroidKeyAttestationStatusStorage()
        : this(Empty())
    {
    }

    public FakeAndroidKeyAttestationStatusStorage(AndroidKeyAttestationStatusList? statusList)
    {
        StatusList = statusList;
    }

    public AndroidKeyAttestationStatusList? StatusList { get; set; }

    public Task<AndroidKeyAttestationStatusList?> GetAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(StatusList);
    }

    public Task UpsertAsync(AndroidKeyAttestationStatusList statusList, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(statusList);
        cancellationToken.ThrowIfCancellationRequested();
        StatusList = statusList;
        return Task.CompletedTask;
    }

    public static AndroidKeyAttestationStatusList Empty()
    {
        return new(new Dictionary<string, AndroidKeyAttestationStatusEntry>());
    }

    public static AndroidKeyAttestationStatusList With(string serialNumber, string? status = "REVOKED", string? reason = "KEY_COMPROMISE")
    {
        return new(new Dictionary<string, AndroidKeyAttestationStatusEntry>
        {
            [serialNumber] = new(status, reason)
        });
    }
}
