using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder.Constants;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation;

public class DefaultAndroidKeyAttestationStatusDecoderTests
{
    private FakeAndroidKeyAttestationStatusCounters Counters { get; set; } = null!;
    private FakeLogger<DefaultAndroidKeyAttestationStatusDecoder> Logger { get; set; } = null!;
    private DefaultAndroidKeyAttestationStatusDecoder Decoder { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Counters = new();
        Logger = new();
        Decoder = new(new DefaultSafeJsonSerializer(new FakeLogger<DefaultSafeJsonSerializer>()), Counters, Logger);
    }

    [Test]
    public void Decode_ReturnsEntries_OfStatusListInGoogleFormat()
    {
        // The format of the status list that Google serves: the keys are serial numbers in lowercase hexadecimal, some of them with decimal digits only.
        const string json = """
                            {
                              "entries": {
                                "6681152659205225093" : {
                                  "status": "REVOKED",
                                  "reason": "KEY_COMPROMISE"
                                },
                                "c35747a084470c3135aeefe2b8d40cd6" : {
                                  "status": "REVOKED",
                                  "reason": "SOFTWARE_FLAW"
                                },
                                "c8966fcb2fbb0d7a": {
                                  "status": "SUSPENDED",
                                  "expires": "2020-11-13",
                                  "reason": "SOFTWARE_FLAW",
                                  "comment": "Bug in keystore causes this key malfunction b/555555"
                                }
                              }
                            }
                            """;

        var result = Decoder.Decode(json);

        Assert.That(result.HasError, Is.False);
        var entries = result.Ok!.Entries;
        Assert.Multiple(() =>
        {
            Assert.That(entries.Keys, Is.EquivalentTo(Values("6681152659205225093", "c35747a084470c3135aeefe2b8d40cd6", "c8966fcb2fbb0d7a")));
            Assert.That(entries["6681152659205225093"].Status, Is.EqualTo("REVOKED"));
            Assert.That(entries["6681152659205225093"].Reason, Is.EqualTo("KEY_COMPROMISE"));
            Assert.That(entries["c35747a084470c3135aeefe2b8d40cd6"].Reason, Is.EqualTo("SOFTWARE_FLAW"));
            Assert.That(entries["c8966fcb2fbb0d7a"].Status, Is.EqualTo("SUSPENDED"));
            Assert.That(Counters.DecodeAnomalies, Is.Empty);
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [Test]
    public void Decode_ReturnsEmptyStatusList_WhenThereAreNoEntries()
    {
        var result = Decoder.Decode("""{"entries":{}}""");

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.Entries, Is.Empty);
    }

    [TestCase("")]
    [TestCase("not json")]
    [TestCase("[]")]
    [TestCase("""{"entries":[]}""")]
    [TestCase("""{"entries":"REVOKED"}""")]
    public void Decode_Fails_WhenStatusListIsNotJsonObjectWithEntriesObject(string json)
    {
        var result = Decoder.Decode(json);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message), Has.One.EqualTo("The status list of the Android attestation keys is not a valid JSON object"));
        });
    }

    [TestCase("{}")]
    [TestCase("""{"entries":null}""")]
    [TestCase("""{"Entries":{"1":{"status":"REVOKED"}}}""")]
    public void Decode_Fails_WhenEntriesAreMissing(string json)
    {
        var result = Decoder.Decode(json);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            Assert.That(Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message), Has.One.EqualTo("The status list of the Android attestation keys has no 'entries' object"));
        });
    }

    [TestCase("xyz")]
    [TestCase("-1a")]
    [TestCase(" 1a")]
    [TestCase("")]
    public void Decode_SkipsEntry_WhenKeyIsNotSerialNumberInHexadecimal(string key)
    {
        var result = Decoder.Decode($$$$"""{"entries":{"{{{{key}}}}":{"status":"REVOKED"},"1a":{"status":"REVOKED"}}}""");

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries.Keys, Is.EqualTo(Values("1a")));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.KeyInvalid, false) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo($"The entry '{key}' of the status list of the Android attestation keys was skipped because its key is not a serial number in hexadecimal"));
        });
    }

    [Test]
    public void Decode_LogsSanitizedKey_WhenKeyContainsControlCharacters()
    {
        var result = Decoder.Decode("""{"entries":{"1a\r\nFAKE\u001b[31m":{"status":"REVOKED"}}}""");

        Assert.That(result.HasError, Is.False);
        var warning = Logger.Entries.Single(static x => x.Level == LogLevel.Warning).Message;
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries, Is.Empty);
            Assert.That(warning, Does.Contain("'1a??FAKE?[31m'"));
            Assert.That(warning, Has.None.Matches<char>(char.IsControl));
        });
    }

    [TestCase("1A2B", "1a2b")]
    [TestCase("001a2b", "1a2b")]
    [TestCase("000", "0")]
    public void Decode_KeepsEntryUnderNormalizedKey_WhenKeyIsNotCanonical(string key, string serialNumber)
    {
        var result = Decoder.Decode($$$$"""{"entries":{"{{{{key}}}}":{"status":"REVOKED"}}}""");

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries.Keys, Is.EqualTo(new[] { serialNumber }));
            Assert.That(result.Ok.Entries[serialNumber].Status, Is.EqualTo("REVOKED"));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.KeyNotCanonical, true) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo($"The key '{key}' of the status list of the Android attestation keys is not in lowercase hexadecimal without leading zeros, so its entry is kept under the serial number '{serialNumber}'"));
        });
    }

    [Test]
    public void Decode_KeepsFirstEntry_WhenKeysNameTheSameSerialNumber()
    {
        var result = Decoder.Decode("""{"entries":{"1a":{"status":"REVOKED"},"01A":{"status":"SUSPENDED"}}}""");

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries.Keys, Is.EqualTo(Values("1a")));
            Assert.That(result.Ok.Entries["1a"].Status, Is.EqualTo("REVOKED"));
        });
    }

    [TestCase("{}")]
    [TestCase("""{"reason":"KEY_COMPROMISE"}""")]
    [TestCase("""{"status":""}""")]
    [TestCase("""{"status":null}""")]
    [TestCase("""{"status":1}""")]
    [TestCase("""{"status":["REVOKED"]}""")]
    [TestCase("\"REVOKED\"")]
    [TestCase("null")]
    [TestCase("[]")]
    public void Decode_KeepsEntryWithoutStatus_WhenStatusIsMissing(string entry)
    {
        // The status list contains only the certificates that don't have a normal valid status, so an entry without a status still names an untrusted certificate.
        var result = Decoder.Decode($$$$"""{"entries":{"1a":{{{{entry}}}}}}""");

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries.Keys, Is.EqualTo(Values("1a")));
            Assert.That(result.Ok.Entries["1a"].Status, Is.Null);
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.StatusMissing, true) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo("The entry for the certificate with the serial number '1a' in the status list of the Android attestation keys has no status, so the certificate is untrusted"));
        });
    }

    [TestCase("VALID")]
    [TestCase("revoked")]
    public void Decode_KeepsEntry_WhenStatusIsUnknown(string status)
    {
        var result = Decoder.Decode($$$$"""{"entries":{"1a":{"status":"{{{{status}}}}","reason":"UNSPECIFIED"}}}""");

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries["1a"].Status, Is.EqualTo(status));
            Assert.That(result.Ok.Entries["1a"].Reason, Is.EqualTo("UNSPECIFIED"));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.StatusUnknown, true) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo($"The entry for the certificate with the serial number '1a' in the status list of the Android attestation keys has the unknown status '{status}', so the certificate is untrusted"));
        });
    }

    [Test]
    public void Decode_IgnoresReason_WhenItIsNotString()
    {
        var result = Decoder.Decode("""{"entries":{"1a":{"status":"REVOKED","reason":1}}}""");

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(result.Ok!.Entries["1a"].Status, Is.EqualTo("REVOKED"));
            Assert.That(result.Ok.Entries["1a"].Reason, Is.Null);
            Assert.That(Counters.DecodeAnomalies, Is.Empty);
        });
    }

    private static string[] Values(params string[] values)
    {
        return values;
    }
}
