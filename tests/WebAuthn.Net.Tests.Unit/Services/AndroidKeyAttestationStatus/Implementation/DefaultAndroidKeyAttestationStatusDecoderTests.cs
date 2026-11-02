using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusDecoder.Constants;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusSerialNumberFormatter;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Enums;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;
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
        Decoder = new(
            new DefaultAndroidKeyAttestationStatusSerialNumberFormatter(),
            new DefaultEnumMemberAttributeSerializer<AndroidKeyAttestationRevocationStatus>(),
            new DefaultEnumMemberAttributeSerializer<AndroidKeyAttestationRevocationReason>(),
            Counters,
            Logger);
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
                                  "status": "REVOKED"
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

        var result = Decoder.Decode(Json(json));

        Assert.That(result.HasError, Is.False);
        var statusList = result.Ok!;
        Assert.Multiple(() =>
        {
            Assert.That(Keys(statusList), Is.EquivalentTo(Values("6681152659205225093", "c35747a084470c3135aeefe2b8d40cd6", "c8966fcb2fbb0d7a")));
            Assert.That(Entry(statusList, "6681152659205225093").Status, Is.EqualTo(AndroidKeyAttestationRevocationStatus.Revoked));
            Assert.That(Entry(statusList, "6681152659205225093").Reason, Is.EqualTo(AndroidKeyAttestationRevocationReason.KeyCompromise));
            Assert.That(Entry(statusList, "c35747a084470c3135aeefe2b8d40cd6").Status, Is.EqualTo(AndroidKeyAttestationRevocationStatus.Revoked));
            Assert.That(Entry(statusList, "c35747a084470c3135aeefe2b8d40cd6").Reason, Is.Null);
            Assert.That(Entry(statusList, "c8966fcb2fbb0d7a").Status, Is.EqualTo(AndroidKeyAttestationRevocationStatus.Suspended));
            Assert.That(Entry(statusList, "c8966fcb2fbb0d7a").Reason, Is.EqualTo(AndroidKeyAttestationRevocationReason.SoftwareFlaw));
            Assert.That(Counters.DecodeAnomalies, Is.Empty);
            Assert.That(Logger.Entries, Is.Empty);
        });
    }

    [TestCase("REVOKED", AndroidKeyAttestationRevocationStatus.Revoked)]
    [TestCase("SUSPENDED", AndroidKeyAttestationRevocationStatus.Suspended)]
    public void Decode_DecodesDocumentedStatus(string status, AndroidKeyAttestationRevocationStatus expected)
    {
        var result = Decoder.Decode(Json($$$$"""{"entries":{"1a":{"status":"{{{{status}}}}"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Entry(result.Ok!, "1a").Status, Is.EqualTo(expected));
            Assert.That(Counters.DecodeAnomalies, Is.Empty);
        });
    }

    [TestCase("UNSPECIFIED", AndroidKeyAttestationRevocationReason.Unspecified)]
    [TestCase("KEY_COMPROMISE", AndroidKeyAttestationRevocationReason.KeyCompromise)]
    [TestCase("CA_COMPROMISE", AndroidKeyAttestationRevocationReason.CaCompromise)]
    [TestCase("SUPERSEDED", AndroidKeyAttestationRevocationReason.Superseded)]
    [TestCase("SOFTWARE_FLAW", AndroidKeyAttestationRevocationReason.SoftwareFlaw)]
    public void Decode_DecodesDocumentedReason(string reason, AndroidKeyAttestationRevocationReason expected)
    {
        var result = Decoder.Decode(Json($$$$"""{"entries":{"1a":{"status":"REVOKED","reason":"{{{{reason}}}}"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Entry(result.Ok!, "1a").Reason, Is.EqualTo(expected));
            Assert.That(Counters.DecodeAnomalies, Is.Empty);
        });
    }

    [Test]
    public void Decode_ReturnsEmptyStatusList_WhenThereAreNoEntries()
    {
        var result = Decoder.Decode(Json("""{"entries":{}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.That(result.Ok!.Entries, Is.Empty);
    }

    [Test]
    public void Decode_Fails_WhenEntriesAreMissing()
    {
        // the default provider doesn't provide such a status list, but another one might
        var result = Decoder.Decode(new AndroidKeyAttestationStatusListJSON(null));

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
        var result = Decoder.Decode(Json($$$$"""{"entries":{"{{{{key}}}}":{"status":"REVOKED"},"1a":{"status":"REVOKED"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Keys(result.Ok!), Is.EqualTo(Values("1a")));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.KeyInvalid, false) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo($"The entry '{key}' of the status list of the Android attestation keys was skipped because its key is not a serial number in hexadecimal"));
        });
    }

    [Test]
    public void Decode_LogsSanitizedKey_WhenKeyContainsControlCharacters()
    {
        var result = Decoder.Decode(Json("""{"entries":{"1a\r\nFAKE\u001b[31m":{"status":"REVOKED"}}}"""));

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
        var result = Decoder.Decode(Json($$$$"""{"entries":{"{{{{key}}}}":{"status":"REVOKED"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Keys(result.Ok!), Is.EqualTo(Values(serialNumber)));
            Assert.That(Entry(result.Ok!, serialNumber).Status, Is.EqualTo(AndroidKeyAttestationRevocationStatus.Revoked));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.KeyNotCanonical, true) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo($"The key '{key}' of the status list of the Android attestation keys is not in lowercase hexadecimal without leading zeros, so its entry is kept under the serial number '{serialNumber}'"));
        });
    }

    [Test]
    public void Decode_SkipsEntry_WhenEarlierEntryHasSameSerialNumber()
    {
        var result = Decoder.Decode(Json("""{"entries":{"1a":{"status":"REVOKED"},"01A":{"status":"SUSPENDED"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Keys(result.Ok!), Is.EqualTo(Values("1a")));
            Assert.That(Entry(result.Ok!, "1a").Status, Is.EqualTo(AndroidKeyAttestationRevocationStatus.Revoked));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.KeyDuplicate, false) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Is.EqualTo(Values("The entry '01A' of the status list of the Android attestation keys was skipped because an earlier entry has the same serial number '1a'")));
        });
    }

    [Test]
    public void Decode_SkipsEntry_WhenEarlierEntryWithNonCanonicalKeyHasSameSerialNumber()
    {
        var result = Decoder.Decode(Json("""{"entries":{"01A":{"status":"SUSPENDED"},"1a":{"status":"REVOKED"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Keys(result.Ok!), Is.EqualTo(Values("1a")));
            Assert.That(Entry(result.Ok!, "1a").Status, Is.EqualTo(AndroidKeyAttestationRevocationStatus.Suspended));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.KeyNotCanonical, true), (AndroidKeyAttestationStatusAnomalies.KeyDuplicate, false) }));
        });
    }

    [TestCase("{}")]
    [TestCase("""{"reason":"KEY_COMPROMISE"}""")]
    [TestCase("""{"status":""}""")]
    [TestCase("""{"status":null}""")]
    [TestCase("null")]
    public void Decode_KeepsEntryWithoutStatus_WhenStatusIsMissing(string entry)
    {
        // The status list contains only the certificates that don't have a normal valid status, so an entry without a status still names an untrusted certificate.
        var result = Decoder.Decode(Json($$$$"""{"entries":{"1a":{{{{entry}}}}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Keys(result.Ok!), Is.EqualTo(Values("1a")));
            Assert.That(Entry(result.Ok!, "1a").Status, Is.Null);
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.StatusMissing, true) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo("The entry for the certificate with the serial number '1a' in the status list of the Android attestation keys has no status, so the certificate is untrusted"));
        });
    }

    [TestCase("VALID")]
    [TestCase("revoked")]
    public void Decode_KeepsEntryWithoutStatus_WhenStatusIsUnknown(string status)
    {
        var result = Decoder.Decode(Json($$$$"""{"entries":{"1a":{"status":"{{{{status}}}}","reason":"UNSPECIFIED"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Keys(result.Ok!), Is.EqualTo(Values("1a")));
            Assert.That(Entry(result.Ok!, "1a").Status, Is.Null);
            Assert.That(Entry(result.Ok!, "1a").Reason, Is.EqualTo(AndroidKeyAttestationRevocationReason.Unspecified));
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.StatusUnknown, true) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo($"The entry for the certificate with the serial number '1a' in the status list of the Android attestation keys has the unknown status '{status}', so the certificate is untrusted"));
        });
    }

    [TestCase("PRIVILEGE_WITHDRAWN")]
    [TestCase("key_compromise")]
    [TestCase("")]
    public void Decode_KeepsEntryWithoutReason_WhenReasonIsUnknown(string reason)
    {
        var result = Decoder.Decode(Json($$$$"""{"entries":{"1a":{"status":"REVOKED","reason":"{{{{reason}}}}"}}}"""));

        Assert.That(result.HasError, Is.False);
        Assert.Multiple(() =>
        {
            Assert.That(Keys(result.Ok!), Is.EqualTo(Values("1a")));
            Assert.That(Entry(result.Ok!, "1a").Status, Is.EqualTo(AndroidKeyAttestationRevocationStatus.Revoked));
            Assert.That(Entry(result.Ok!, "1a").Reason, Is.Null);
            Assert.That(Counters.DecodeAnomalies, Is.EqualTo(new[] { (AndroidKeyAttestationStatusAnomalies.ReasonUnknown, true) }));
            Assert.That(
                Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
                Has.One.EqualTo($"The entry for the certificate with the serial number '1a' in the status list of the Android attestation keys has the unknown reason '{reason}', so the reason is ignored"));
        });
    }

    [Test]
    public void Decode_LogsSanitizedValues_WhenStatusAndReasonContainControlCharacters()
    {
        var result = Decoder.Decode(Json("""{"entries":{"1a":{"status":"REVOKED\r\nFAKE","reason":"KEY\u001b[31m"}}}"""));

        Assert.That(result.HasError, Is.False);
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message).ToArray();
        Assert.Multiple(() =>
        {
            Assert.That(warnings, Has.Length.EqualTo(2));
            Assert.That(warnings, Has.One.Contains("the unknown status 'REVOKED??FAKE'"));
            Assert.That(warnings, Has.One.Contains("the unknown reason 'KEY?[31m'"));
            Assert.That(string.Concat(warnings), Has.None.Matches<char>(char.IsControl));
        });
    }

    private static string[] Keys(AndroidKeyAttestationStatusList statusList)
    {
        return statusList.Entries.Keys.ToArray();
    }

    private static AndroidKeyAttestationStatusEntry Entry(AndroidKeyAttestationStatusList statusList, string serialNumber)
    {
        return statusList.Entries[serialNumber];
    }

    private static AndroidKeyAttestationStatusListJSON Json(string json)
    {
        return JsonSerializer.Deserialize<AndroidKeyAttestationStatusListJSON>(json)!;
    }

    private static string[] Values(params string[] values)
    {
        return values;
    }
}
