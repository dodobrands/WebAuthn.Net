using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus;

namespace WebAuthn.Net.DSL.Fakes;

/// <summary>
///     An HTTP client of the status list of the Android attestation keys that doesn't go to the network: it returns an empty status list.
/// </summary>
public class FakeAndroidKeyAttestationStatusHttpClient : IAndroidKeyAttestationStatusHttpClient
{
    private int _calls;

    public int Calls => _calls;

    public Task<string> DownloadStatusListAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Interlocked.Increment(ref _calls);
        return Task.FromResult("""{"entries":{}}""");
    }
}
