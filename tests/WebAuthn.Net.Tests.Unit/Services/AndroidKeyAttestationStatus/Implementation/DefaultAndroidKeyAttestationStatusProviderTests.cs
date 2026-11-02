using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusProvider;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusProvider.Constants;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class DefaultAndroidKeyAttestationStatusProviderTests
{
    private const string EmbeddedStatusListResourceName = "WebAuthn.Net.DSL.Fakes.FakeResources.android-key-status.json";
    private static readonly Assembly EmbeddedStatusListAssembly = typeof(DefaultAndroidKeyAttestationStatusProviderTests).Assembly;

    private StubStatusHttpClient HttpClient { get; set; } = null!;
    private FakeAndroidKeyAttestationStatusCounters Counters { get; set; } = null!;
    private FakeLogger<DefaultAndroidKeyAttestationStatusProvider> Logger { get; set; } = null!;
    private DefaultAndroidKeyAttestationStatusProvider Provider { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        HttpClient = new();
        Counters = new();
        Logger = new();
        Provider = new(HttpClient, new DefaultSafeJsonSerializer(new FakeLogger<DefaultSafeJsonSerializer>()), Counters, Logger);
    }

    // ---------------------------------------------------------------------------------------------
    // The download

    [Test]
    public async Task DownloadStatusListAsync_ReturnsStatusList_WhenItMatchesJsonFormat()
    {
        HttpClient.Response = """{"entries":{"1a":{"status":"REVOKED","reason":"KEY_COMPROMISE"},"2b":{"status":"SUSPENDED"}}}""";

        var result = await Provider.DownloadStatusListAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries?.Keys, Is.EquivalentTo(Values("1a", "2b")));
            Assert.That(result.Ok.Entries?["1a"]?.Status, Is.EqualTo("REVOKED"));
            Assert.That(result.Ok.Entries?["1a"]?.Reason, Is.EqualTo("KEY_COMPROMISE"));
            Assert.That(result.Ok.Entries?["2b"]?.Reason, Is.Null);
            Assert.That(Counters.DownloadFailures, Is.Empty);
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_IgnoresMembersThatAreNotUsed_WhateverTheirType()
    {
        // 'expires' and 'comment' are documented but not used, so their format can't make the status list invalid
        HttpClient.Response = """{"entries":{"1a":{"status":"REVOKED","expires":20201113,"comment":["Bug"],"unknown":{"a":1}}},"unknown":1}""";

        var result = await Provider.DownloadStatusListAsync(CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries?["1a"]?.Status, Is.EqualTo("REVOKED"));
            Assert.That(Counters.DownloadFailures, Is.Empty);
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_Fails_WhenRequestFails()
    {
        HttpClient.Exception = new HttpRequestException("Response status code does not indicate success: 503 (Service Unavailable).");

        var result = await Provider.DownloadStatusListAsync(CancellationToken.None);

        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Counters.DownloadFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusDownloadFailures.RequestFailed)));
            Assert.That(warnings.Select(static x => x.Message), Is.EqualTo(Values("The status list of the Android attestation keys can't be downloaded")));
            Assert.That(warnings.Single().Exception, Is.SameAs(HttpClient.Exception));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_Fails_WhenConnectionIsBroken()
    {
        HttpClient.Exception = new IOException("The response ended prematurely.");

        var result = await Provider.DownloadStatusListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Counters.DownloadFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusDownloadFailures.RequestFailed)));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_Fails_WhenDownloadTimesOut()
    {
        HttpClient.Exception = new TimeoutException("The download timed out");

        var result = await Provider.DownloadStatusListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Counters.DownloadFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusDownloadFailures.Timeout)));
        });
    }

    [Test]
    public async Task DownloadStatusListAsync_PropagatesOtherExceptions()
    {
        // for example, an open circuit breaker of a resilience policy: the background ingestion logs and counts it
        HttpClient.Exception = new InvalidOperationException("The circuit is open");

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await Provider.DownloadStatusListAsync(CancellationToken.None));
        Assert.That(Counters.DownloadFailures, Is.Empty);
    }

    [TestCase("")]
    [TestCase("not json")]
    [TestCase("[]")]
    [TestCase("null")]
    [TestCase("{}")]
    [TestCase("""{"entries":null}""")]
    [TestCase("""{"Entries":{"1a":{"status":"REVOKED"}}}""")]
    [TestCase("""{"entries":[]}""")]
    [TestCase("""{"entries":"REVOKED"}""")]
    // an entry or a member of an entry of the wrong type
    [TestCase("""{"entries":{"1a":"REVOKED"}}""")]
    [TestCase("""{"entries":{"1a":[]}}""")]
    [TestCase("""{"entries":{"1a":{"status":1}}}""")]
    [TestCase("""{"entries":{"1a":{"status":["REVOKED"]}}}""")]
    [TestCase("""{"entries":{"1a":{"status":"REVOKED","reason":1}}}""")]
    public async Task DownloadStatusListAsync_Fails_WhenStatusListDoesNotMatchJsonFormat(string json)
    {
        HttpClient.Response = json;

        var result = await Provider.DownloadStatusListAsync(CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Counters.DownloadFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusDownloadFailures.ListInvalid)));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Is.EqualTo(Values("The downloaded status list of the Android attestation keys doesn't match its JSON format (an object with an 'entries' object)")));
        });
    }

    // ---------------------------------------------------------------------------------------------
    // The status list embedded in the application

    [Test]
    public async Task LoadEmbeddedStatusListAsync_ReturnsStatusList_FromManifestResource()
    {
        var result = await Provider.LoadEmbeddedStatusListAsync(EmbeddedStatusListAssembly, EmbeddedStatusListResourceName, CancellationToken.None);

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries?.Keys, Is.EquivalentTo(Values("6681152659205225093", "c35747a084470c3135aeefe2b8d40cd6", "c8966fcb2fbb0d7a")));
            Assert.That(HttpClient.Calls, Is.Zero);
            Assert.That(Counters.EmbeddedFailures, Is.Empty);
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task LoadEmbeddedStatusListAsync_Fails_WhenResourceIsNotFound()
    {
        var result = await Provider.LoadEmbeddedStatusListAsync(EmbeddedStatusListAssembly, "WebAuthn.Net.Missing.status.json", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Counters.EmbeddedFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusEmbeddedFailures.ResourceNotFound)));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.Exactly(1).Contains("doesn't contain the manifest resource 'WebAuthn.Net.Missing.status.json'").And.Contains(EmbeddedStatusListResourceName));
        });
    }

    [Test]
    public async Task LoadEmbeddedStatusListAsync_Fails_WhenResourceDoesNotMatchJsonFormat()
    {
        var result = await Provider.LoadEmbeddedStatusListAsync(EmbeddedStatusListAssembly, "WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt", CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Counters.EmbeddedFailures, Is.EqualTo(Values(AndroidKeyAttestationStatusEmbeddedFailures.ListInvalid)));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.StartsWith("The status list of the Android attestation keys embedded in the application (the manifest resource 'WebAuthn.Net.DSL.Fakes.FakeResources.blob.jwt'"));
        });
    }

    [Test]
    public async Task LoadEmbeddedStatusListAsync_Throws_WhenArgumentsAreMissing()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await Provider.LoadEmbeddedStatusListAsync(null!, EmbeddedStatusListResourceName, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(async () => await Provider.LoadEmbeddedStatusListAsync(EmbeddedStatusListAssembly, " ", CancellationToken.None));
    }

    private static string[] Values(params string[] values)
    {
        return values;
    }

    private sealed class StubStatusHttpClient : IAndroidKeyAttestationStatusHttpClient
    {
        public string Response { get; set; } = """{"entries":{}}""";

        public Exception? Exception { get; set; }

        public int Calls { get; private set; }

        public Task<string> DownloadStatusListAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Exception is null
                ? Task.FromResult(Response)
                : Task.FromException<string>(Exception);
        }
    }
}
