using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusIngestService;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class DefaultAndroidKeyAttestationStatusIngestServiceTests
{
    private FakeAndroidKeyAttestationStatusStorage Storage { get; set; } = null!;
    private FakeLogger<DefaultAndroidKeyAttestationStatusIngestService> Logger { get; set; } = null!;
    private DefaultAndroidKeyAttestationStatusIngestService IngestService { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Storage = new(null);
        Logger = new();
        IngestService = new(Storage, Logger);
    }

    [Test]
    public async Task UpsertAsync_ReplacesStatusListInUse()
    {
        Storage.StatusList = FakeAndroidKeyAttestationStatusStorage.With("1a");
        var statusList = FakeAndroidKeyAttestationStatusStorage.With("2b");

        await IngestService.UpsertAsync(statusList, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Storage.StatusList, Is.SameAs(statusList));
            Assert.That(Information(), Is.EqualTo(Values("The status list of the Android attestation keys with 1 entries was ingested")));
        });
    }

    [Test]
    public async Task UpsertEmbeddedAsync_StoresStatusList_WhenNoStatusListIsInUse()
    {
        var statusList = FakeAndroidKeyAttestationStatusStorage.With("1a");

        await IngestService.UpsertEmbeddedAsync(statusList, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Storage.StatusList, Is.SameAs(statusList));
            Assert.That(Information(), Is.EqualTo(Values("The status list of the Android attestation keys with 1 entries embedded in the application was ingested")));
        });
    }

    [Test]
    public async Task UpsertEmbeddedAsync_KeepsStatusListInUse()
    {
        // for example, a persistent storage keeps the status list downloaded before the restart of the application, which is newer than the embedded one
        var statusListInUse = FakeAndroidKeyAttestationStatusStorage.With("1a");
        Storage.StatusList = statusListInUse;

        await IngestService.UpsertEmbeddedAsync(FakeAndroidKeyAttestationStatusStorage.With("2b"), CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(Storage.StatusList, Is.SameAs(statusListInUse));
            Assert.That(Information(), Is.EqualTo(Values("The status list of the Android attestation keys embedded in the application was not ingested because a status list is already in use")));
            Assert.That(Logger.Entries.Where(static x => x.Level >= LogLevel.Warning), Is.Empty);
        });
    }

    private string[] Information()
    {
        return Logger.Entries.Where(static x => x.Level == LogLevel.Information).Select(static x => x.Message).ToArray();
    }

    private static string[] Values(params string[] values)
    {
        return values;
    }
}
