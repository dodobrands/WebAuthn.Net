using System;
using System.Linq;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation;

public class DefaultFidoMetadataDecoderPayloadTests
{
    private const string UnknownStatus = "SOME_FUTURE_STATUS";
    private static readonly ulong[] ExpectedVendorPrototypeConfigCommands = [1];
    private static readonly ulong[] ExpectedAuthenticatorConfigCommands = [2, 3];
    private static readonly string[] ExpectedTransportsForReset = ["usb", "nfc"];
    private static readonly string[] ExpectedIgnoredStatusReports = [UnknownStatus];

    private DefaultFidoMetadataDecoder Decoder { get; set; } = null!;
    private FakeLogger<DefaultFidoMetadataDecoder> Logger { get; set; } = null!;
    private FakeFidoMetadataCounters Counters { get; set; } = null!;

    [SetUp]
    public void SetupServices()
    {
        Logger = new();
        Counters = new();
        Decoder = new(
            new DefaultEnumMemberAttributeSerializer<UserVerificationMethod>(),
            new DefaultEnumMemberAttributeSerializer<ProtocolFamily>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticationAlgorithm>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyRepresentationFormat>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttestationType>(),
            new DefaultEnumMemberAttributeSerializer<KeyProtectionType>(),
            new DefaultEnumMemberAttributeSerializer<MatcherProtectionType>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachmentHint>(),
            new DefaultEnumMemberAttributeSerializer<TransactionConfirmationDisplayType>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorStatus>(),
            Counters,
            Logger);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenPayloadIsValid()
    {
        var payload = FakeMetadataBlobPayloadJsonFactory.Create();

        var decoded = DecodeSuccessfully(payload);

        var statement = decoded.Entries.Single().MetadataStatement;
        Assert.That(decoded.NextUpdate, Is.EqualTo(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero)));
        Assert.That(statement?.UserVerificationDetails, Has.Length.EqualTo(1));
        Assert.That(statement?.AuthenticatorGetInfo?.Aaguid, Is.EqualTo(Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid)));
        Assert.That(Logger.Entries, Is.Empty);
        Assert.That(Counters.DecodeStarts, Is.EqualTo(1));
        Assert.That(Counters.SuccessfulDecodeEnds, Is.EqualTo(1));
        Assert.That(Counters.FailedDecodeEnds, Is.Zero);
        Assert.That(Counters.SkippedEntries, Is.Empty);
        Assert.That(Counters.IgnoredStatusReports, Is.Empty);
    }

    [TestCase("NOT_FIDO_CERTIFIED", AuthenticatorStatus.NOT_FIDO_CERTIFIED)]
    [TestCase("FIDO_CERTIFIED", AuthenticatorStatus.FIDO_CERTIFIED)]
    [TestCase("USER_VERIFICATION_BYPASS", AuthenticatorStatus.USER_VERIFICATION_BYPASS)]
    [TestCase("ATTESTATION_KEY_COMPROMISE", AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE)]
    [TestCase("USER_KEY_REMOTE_COMPROMISE", AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE)]
    [TestCase("USER_KEY_PHYSICAL_COMPROMISE", AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE)]
    [TestCase("UPDATE_AVAILABLE", AuthenticatorStatus.UPDATE_AVAILABLE)]
    [TestCase("RETIRED", AuthenticatorStatus.RETIRED)]
    [TestCase("REVOKED", AuthenticatorStatus.REVOKED)]
    [TestCase("SELF_ASSERTION_SUBMITTED", AuthenticatorStatus.SELF_ASSERTION_SUBMITTED)]
    [TestCase("FIDO_CERTIFIED_L1", AuthenticatorStatus.FIDO_CERTIFIED_L1)]
    [TestCase("FIDO_CERTIFIED_L1plus", AuthenticatorStatus.FIDO_CERTIFIED_L1plus)]
    [TestCase("FIDO_CERTIFIED_L2", AuthenticatorStatus.FIDO_CERTIFIED_L2)]
    [TestCase("FIDO_CERTIFIED_L2plus", AuthenticatorStatus.FIDO_CERTIFIED_L2plus)]
    [TestCase("FIDO_CERTIFIED_L3", AuthenticatorStatus.FIDO_CERTIFIED_L3)]
    [TestCase("FIDO_CERTIFIED_L3plus", AuthenticatorStatus.FIDO_CERTIFIED_L3plus)]
    [TestCase("FIPS140_CERTIFIED_L1", AuthenticatorStatus.FIPS140_CERTIFIED_L1)]
    [TestCase("FIPS140_CERTIFIED_L2", AuthenticatorStatus.FIPS140_CERTIFIED_L2)]
    [TestCase("FIPS140_CERTIFIED_L3", AuthenticatorStatus.FIPS140_CERTIFIED_L3)]
    [TestCase("FIPS140_CERTIFIED_L4", AuthenticatorStatus.FIPS140_CERTIFIED_L4)]
    public void DefaultFidoMetadataDecoder_Decode_WhenStatusIsDefinedBySpecification(string status, AuthenticatorStatus expectedStatus)
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        // The test cases list every value of the AuthenticatorStatus enum defined by the specification.
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(x => FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"] = new JsonArray(new JsonObject
        {
            ["status"] = status,
            ["effectiveDate"] = "2026-10-01"
        }));

        var decoded = DecodeSuccessfully(payload);

        Assert.That(decoded.Entries.Single().StatusReports.Single().Status, Is.EqualTo(expectedStatus));
        Assert.That(Logger.Entries, Is.Empty);
        Assert.That(Counters.IgnoredStatusReports, Is.Empty);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenUserVerificationDetailsIsAbsent()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#dom-metadatastatement-userverificationdetails
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => FakeMetadataBlobPayloadJsonFactory.GetMetadataStatement(x).Remove("userVerificationDetails"));

        var decoded = DecodeSuccessfully(payload);

        var statement = decoded.Entries.Single().MetadataStatement;
        Assert.That(statement, Is.Not.Null);
        Assert.That(statement?.UserVerificationDetails, Is.Null);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenNextUpdateIsAbsent()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayload-nextupdate
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => x.Remove("nextUpdate"));

        var decoded = DecodeSuccessfully(payload);

        Assert.That(decoded.NextUpdate, Is.Null);
        Assert.That(decoded.Entries, Has.Length.EqualTo(1));
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenNextUpdateIsInvalid()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayload-nextupdate
        // FIDO servers should ensure this field is not required by their code.
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => x["nextUpdate"] = "not a date");

        var decoded = DecodeSuccessfully(payload);

        Assert.That(decoded.NextUpdate, Is.Null);
        Assert.That(decoded.Entries, Has.Length.EqualTo(1));
        Assert.That(Logger.Entries.Any(static x => x.Level == LogLevel.Warning && x.Message.Contains("nextUpdate", StringComparison.Ordinal)), Is.True);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenEntriesAreEmpty()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayload-entries
        // List of zero or more MetadataBLOBPayloadEntry objects.
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => x["entries"] = new JsonArray());

        var decoded = DecodeSuccessfully(payload);

        Assert.That(decoded.Entries, Is.Empty);
        Assert.That(Logger.Entries, Is.Empty);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenOneOfEntriesIsInvalid()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-blob-proc-rules
        // It is possible that an MDS entry representing an authenticator disappears in a future update of the BLOB. This should not affect the processing of any other MDS entries.
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x =>
        {
            var invalidEntry = FakeMetadataBlobPayloadJsonFactory.AddEntry(x, FakeMetadataBlobPayloadJsonFactory.SecondAaguid);
            invalidEntry["attestationCertificateKeyIdentifiers"] = new JsonArray("not a hex string");
        });

        var decoded = DecodeSuccessfully(payload);

        Assert.That(decoded.Entries, Has.Length.EqualTo(1));
        Assert.That(decoded.Entries[0].Aaguid, Is.EqualTo(Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid)));
        var skippedEntryWarning = Logger.Entries.SingleOrDefault(static x => x.Level == LogLevel.Warning);
        Assert.That(skippedEntryWarning, Is.Not.Null);
        Assert.That(skippedEntryWarning?.Message, Does.Contain(FakeMetadataBlobPayloadJsonFactory.SecondAaguid));
        Assert.That(skippedEntryWarning?.Message, Does.Contain("attestationCertificateKeyIdentifiers"));
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAllEntriesAreInvalid()
    {
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x =>
        {
            var secondEntry = FakeMetadataBlobPayloadJsonFactory.AddEntry(x, FakeMetadataBlobPayloadJsonFactory.SecondAaguid);
            secondEntry.Remove("statusReports");
            FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["attestationCertificateKeyIdentifiers"] = new JsonArray("not a hex string");
        });

        var result = Decoder.Decode(payload);

        Assert.That(result.HasError, Is.True);
        Assert.That(Logger.Entries.Count(static x => x.Level == LogLevel.Warning), Is.EqualTo(3));
        Assert.That(Logger.Entries.Any(static x => x.Message.Contains(FakeMetadataBlobPayloadJsonFactory.Aaguid, StringComparison.Ordinal) && x.Message.Contains("attestationCertificateKeyIdentifiers", StringComparison.Ordinal)), Is.True);
        Assert.That(Logger.Entries.Any(static x => x.Message.Contains(FakeMetadataBlobPayloadJsonFactory.SecondAaguid, StringComparison.Ordinal) && x.Message.Contains("statusReports", StringComparison.Ordinal)), Is.True);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenEntriesAreMissing()
    {
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => x.Remove("entries"));

        var result = Decoder.Decode(payload);

        Assert.That(result.HasError, Is.True);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenEntryIsNull()
    {
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => FakeMetadataBlobPayloadJsonFactory.GetEntries(x).Add(null));

        var decoded = DecodeSuccessfully(payload);

        Assert.That(decoded.Entries, Has.Length.EqualTo(1));
        Assert.That(Logger.Entries.Count(static x => x.Level == LogLevel.Warning), Is.EqualTo(1));
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenEntryHasNoIdentifiers()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayloadentry-attestationcertificatekeyidentifiers
        // This field MUST be set if neither aaid nor aaguid are set.
        DecodeWithInvalidSecondEntry(static x => x.Remove("aaguid"), "aaid/aaguid/attestationCertificateKeyIdentifiers");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenEntryHasRogueListUrlWithoutHash()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayloadentry-roguelisthash
        // This hash value MUST be present and non-empty whenever rogueListURL is present.
        DecodeWithInvalidSecondEntry(static x => x["rogueListURL"] = "https://example.com/rogue-list", "rogueListHash");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenEntryHasNoStatusReports()
    {
        DecodeWithInvalidSecondEntry(static x => x.Remove("statusReports"), "statusReports");
    }

    [TestCase("10")]
    [TestCase("999")]
    [TestCase("REVOKED,RETIRED")]
    [TestCase("retired")]
    [TestCase("")]
    [TestCase("SOME_FUTURE_STATUS")]
    public void DefaultFidoMetadataDecoder_Decode_WhenStatusIsUnknown_IgnoresOnlyTheStatusReport(string status)
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        // More values might be added in the future. FIDO Servers MUST silently ignore all unknown AuthenticatorStatus values.
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(x =>
        {
            var statusReports = FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"]?.AsArray() ?? throw new InvalidOperationException("No status reports");
            statusReports.Add(new JsonObject
            {
                ["status"] = status,
                ["effectiveDate"] = "2026-10-01"
            });
        });

        var decoded = DecodeSuccessfully(payload);

        var entry = decoded.Entries.Single();
        Assert.That(entry.StatusReports, Has.Length.EqualTo(1));
        Assert.That(entry.StatusReports[0].Status, Is.EqualTo(AuthenticatorStatus.FIDO_CERTIFIED_L1));
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Exception, Is.Null);
        Assert.That(warnings[0].Message, Does.Contain("status report #1").And.Contain($"'{status}'"));
        Assert.That(Counters.IgnoredStatusReports, Is.EqualTo(new[] { status }));
        Assert.That(Counters.SkippedEntries, Is.Empty);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAllStatusReportsAreUnknown_KeepsEntryWithoutStatusReports()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"] = new JsonArray(new JsonObject
        {
            ["status"] = UnknownStatus,
            ["effectiveDate"] = "2026-10-01"
        }));

        var decoded = DecodeSuccessfully(payload);

        var entry = decoded.Entries.Single();
        Assert.That(entry.StatusReports, Is.Empty);
        Assert.That(Counters.IgnoredStatusReports, Is.EqualTo(ExpectedIgnoredStatusReports));
        Assert.That(Counters.SkippedEntries, Is.Empty);
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenStatusIsNull()
    {
        DecodeWithInvalidSecondEntry(static x => x["statusReports"] = new JsonArray(new JsonObject
        {
            ["status"] = null,
            ["effectiveDate"] = "2026-10-01"
        }), "statusReports[0].status");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAttestationRootCertificateIsNull()
    {
        DecodeWithInvalidSecondEntry(static x => GetMetadataStatementOf(x)["attestationRootCertificates"] = new JsonArray((JsonNode?) null), "metadataStatement.attestationRootCertificates");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAttestationRootCertificateIsNotBase64()
    {
        // Convert.FromBase64 ignores whitespace, so the invalid string must contain characters outside of the base64 alphabet
        DecodeWithInvalidSecondEntry(static x => GetMetadataStatementOf(x)["attestationRootCertificates"] = new JsonArray("!!!not-a-base64-string!!!"), "metadataStatement.attestationRootCertificates");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenProtocolFamilyIsMissing()
    {
        DecodeWithInvalidSecondEntry(static x => GetMetadataStatementOf(x).Remove("protocolFamily"), "metadataStatement.protocolFamily");
    }

    [TestCase("unknown_key_protection_type")]
    [TestCase(null)]
    public void DefaultFidoMetadataDecoder_Decode_WhenKeyProtectionContainsUnknownValue(string? keyProtection)
    {
        DecodeWithInvalidSecondEntry(x => GetMetadataStatementOf(x)["keyProtection"] = new JsonArray(keyProtection), "metadataStatement.keyProtection");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAttestationTypesContainsUnknownValue()
    {
        DecodeWithInvalidSecondEntry(static x => GetMetadataStatementOf(x)["attestationTypes"] = new JsonArray("basic_full", "unknown_attestation_type"), "metadataStatement.attestationTypes");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAuthenticatorGetInfoVersionsIsMissing()
    {
        // https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorGetInfo
        DecodeWithInvalidSecondEntry(static x => GetAuthenticatorGetInfoOf(x).Remove("versions"), "metadataStatement.authenticatorGetInfo.versions");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAuthenticatorGetInfoAaguidIsInvalid()
    {
        DecodeWithInvalidSecondEntry(static x => GetAuthenticatorGetInfoOf(x)["aaguid"] = "not an aaguid", "metadataStatement.authenticatorGetInfo.aaguid");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenBiometricStatusReportModalityIsUnknown()
    {
        DecodeWithInvalidSecondEntry(static x => x["biometricStatusReports"] = new JsonArray(new JsonObject
        {
            ["certLevel"] = 1,
            ["modality"] = "unknown_modality"
        }), "biometricStatusReports");
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenStatusIsRetired()
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x =>
        {
            var statusReports = FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"]?.AsArray() ?? throw new InvalidOperationException("No status reports");
            statusReports.Add(new JsonObject
            {
                ["status"] = "RETIRED",
                ["effectiveDate"] = "2026-10-01"
            });
        });

        var decoded = DecodeSuccessfully(payload);

        var statuses = decoded.Entries.Single().StatusReports.Select(static x => x.Status).ToArray();
        Assert.That(statuses, Does.Contain(AuthenticatorStatus.RETIRED));
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAuthenticatorGetInfoContainsCtap23Members()
    {
        // https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorGetInfo
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x =>
        {
            var getInfo = FakeMetadataBlobPayloadJsonFactory.GetAuthenticatorGetInfo(x);
            getInfo["vendorPrototypeConfigCommands"] = new JsonArray(1);
            getInfo["uvCountSinceLastPinEntry"] = 5;
            getInfo["longTouchForReset"] = true;
            getInfo["encIdentifier"] = "00112233";
            getInfo["transportsForReset"] = new JsonArray("usb", "nfc");
            getInfo["pinComplexityPolicy"] = true;
            getInfo["pinComplexityPolicyURL"] = "68747470733a2f2f797562692e636f2f70696e";
            getInfo["maxPINLength"] = 63;
            getInfo["encCredStoreState"] = "44556677";
            getInfo["authenticatorConfigCommands"] = new JsonArray(2, 3);
        });

        var decoded = DecodeSuccessfully(payload);

        var getInfo = decoded.Entries.Single().MetadataStatement?.AuthenticatorGetInfo;
        Assert.That(getInfo, Is.Not.Null);
        Assert.That(getInfo?.VendorPrototypeConfigCommands, Is.EqualTo(ExpectedVendorPrototypeConfigCommands));
        Assert.That(getInfo?.UvCountSinceLastPinEntry, Is.EqualTo(5UL));
        Assert.That(getInfo?.LongTouchForReset, Is.True);
        Assert.That(getInfo?.EncIdentifier, Is.EqualTo("00112233"));
        Assert.That(getInfo?.TransportsForReset, Is.EqualTo(ExpectedTransportsForReset));
        Assert.That(getInfo?.PinComplexityPolicy, Is.True);
        Assert.That(getInfo?.PinComplexityPolicyURL, Is.EqualTo("68747470733a2f2f797562692e636f2f70696e"));
        Assert.That(getInfo?.MaxPINLength, Is.EqualTo(63UL));
        Assert.That(getInfo?.EncCredStoreState, Is.EqualTo("44556677"));
        Assert.That(getInfo?.AuthenticatorConfigCommands, Is.EqualTo(ExpectedAuthenticatorConfigCommands));
    }

    [TestCase("531126d6e717415c93203d9aa6981239")]
    [TestCase("531126d6-e717-415c-9320-3d9aa6981239")]
    [TestCase("UxEm1ucXQVyTID2appgSOQ==")]
    [TestCase("UxEm1ucXQVyTID2appgSOQ")]
    public void DefaultFidoMetadataDecoder_Decode_WhenAuthenticatorGetInfoAaguidIsHexOrBase64(string aaguid)
    {
        // https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#sctn-type-agid
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(x => FakeMetadataBlobPayloadJsonFactory.GetAuthenticatorGetInfo(x)["aaguid"] = aaguid);

        var decoded = DecodeSuccessfully(payload);

        var getInfo = decoded.Entries.Single().MetadataStatement?.AuthenticatorGetInfo;
        Assert.That(getInfo?.Aaguid, Is.EqualTo(Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid)));
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenAuthenticatorGetInfoAlgorithmHasUnknownType()
    {
        // https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialparameters-type
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x => FakeMetadataBlobPayloadJsonFactory.GetAuthenticatorGetInfo(x)["algorithms"] = new JsonArray(
            new JsonObject
            {
                ["type"] = "public-key",
                ["alg"] = -7
            },
            new JsonObject
            {
                ["type"] = "unknown-credential-type",
                ["alg"] = -8
            }));

        var decoded = DecodeSuccessfully(payload);

        var algorithms = decoded.Entries.Single().MetadataStatement?.AuthenticatorGetInfo?.Algorithms;
        Assert.That(algorithms, Has.Length.EqualTo(1));
        Assert.That(algorithms?[0].Alg, Is.EqualTo(-7));
    }

    [Test]
    public void DefaultFidoMetadataDecoder_Decode_WhenDateContainsOffset()
    {
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(static x =>
        {
            var statusReport = FakeMetadataBlobPayloadJsonFactory.GetEntry(x)["statusReports"]?[0]?.AsObject() ?? throw new InvalidOperationException("No status reports");
            statusReport["effectiveDate"] = "2026-09-30T10:00:00+03:00";
        });

        var decoded = DecodeSuccessfully(payload);

        var effectiveDate = decoded.Entries.Single().StatusReports.Single().EffectiveDate;
        Assert.That(effectiveDate, Is.EqualTo(new DateTimeOffset(2026, 9, 30, 7, 0, 0, TimeSpan.Zero)));
        Assert.That(effectiveDate?.Offset, Is.EqualTo(TimeSpan.Zero));
    }

    private static JsonObject GetMetadataStatementOf(JsonObject entry)
    {
        return entry["metadataStatement"]?.AsObject() ?? throw new InvalidOperationException("The metadata payload entry has no metadata statement");
    }

    private static JsonObject GetAuthenticatorGetInfoOf(JsonObject entry)
    {
        return GetMetadataStatementOf(entry)["authenticatorGetInfo"]?.AsObject() ?? throw new InvalidOperationException("The metadata statement has no authenticatorGetInfo");
    }

    /// <summary>
    ///     Decodes a payload with two entries where the second one is made invalid by <paramref name="configureSecondEntry" />
    ///     and verifies that only the second entry is skipped and the skip is logged with the expected member path.
    /// </summary>
    private void DecodeWithInvalidSecondEntry(Action<JsonObject> configureSecondEntry, string expectedFailedMember)
    {
        var payload = FakeMetadataBlobPayloadJsonFactory.Create(x => configureSecondEntry(FakeMetadataBlobPayloadJsonFactory.AddEntry(x, FakeMetadataBlobPayloadJsonFactory.SecondAaguid)));

        var decoded = DecodeSuccessfully(payload);

        Assert.That(decoded.Entries, Has.Length.EqualTo(1));
        Assert.That(decoded.Entries[0].Aaguid, Is.EqualTo(Guid.Parse(FakeMetadataBlobPayloadJsonFactory.Aaguid)));
        var warnings = Logger.Entries.Where(static x => x.Level == LogLevel.Warning).ToArray();
        Assert.That(warnings, Has.Length.EqualTo(1));
        Assert.That(warnings[0].Exception, Is.Null);
        Assert.That(warnings[0].Message, Does.Contain($"'{expectedFailedMember}'"));
        Assert.That(Counters.SkippedEntries, Is.EqualTo(new[] { expectedFailedMember.Replace("[0]", "[]", StringComparison.Ordinal) }));
        Assert.That(Counters.IgnoredStatusReports, Is.Empty);
    }

    private MetadataBlobPayload DecodeSuccessfully(MetadataBLOBPayloadJSON payload)
    {
        var result = Decoder.Decode(payload);
        if (result.HasError)
        {
            throw new InvalidOperationException("Can't decode metadata");
        }

        return result.Ok;
    }
}
