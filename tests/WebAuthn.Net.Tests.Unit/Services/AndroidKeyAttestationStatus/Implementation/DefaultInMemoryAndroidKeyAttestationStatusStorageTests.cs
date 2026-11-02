using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;
using WebAuthn.Net.Storage.AndroidKeyAttestationStatus.Implementation;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class DefaultInMemoryAndroidKeyAttestationStatusStorageTests
{
    [Test]
    public async Task GetAsync_ReturnsNull_BeforeTheFirstUpsert()
    {
        var storage = new DefaultInMemoryAndroidKeyAttestationStatusStorage();

        var statusList = await storage.GetAsync(CancellationToken.None);

        Assert.That(statusList, Is.Null);
    }

    [Test]
    public async Task UpsertAsync_ReplacesTheStatusListInUse()
    {
        var storage = new DefaultInMemoryAndroidKeyAttestationStatusStorage();
        var first = new AndroidKeyAttestationStatusList(new Dictionary<string, AndroidKeyAttestationStatusEntry> { ["1"] = new("REVOKED", null) });
        var second = new AndroidKeyAttestationStatusList(new Dictionary<string, AndroidKeyAttestationStatusEntry>());

        await storage.UpsertAsync(first, CancellationToken.None);
        var afterFirst = await storage.GetAsync(CancellationToken.None);
        await storage.UpsertAsync(second, CancellationToken.None);
        var afterSecond = await storage.GetAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(afterFirst, Is.SameAs(first));
            Assert.That(afterSecond, Is.SameAs(second));
        });
    }
}
