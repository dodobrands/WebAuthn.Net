using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.DSL.Fakes.Storage;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Apple;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.None;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;
using WebAuthn.Net.Services.Common.ChallengeGenerator.Implementation;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Metrics.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Implementation;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;

[TestFixture]
public abstract class AbstractRegistrationCeremonyServiceTests
{
    [SetUp]
    public virtual async Task SetupServices()
    {
        ConfigurationManager = new();
        ConfigurationManager.AddInMemoryCollection(GetConfiguration());
        var webAuthnOptions = FakeWebAuthnOptionsFactory.Create(ConfigurationManager);
        ConfigureWebAuthnOptions(webAuthnOptions);
        var optionsCache = new OptionsCache<WebAuthnOptions>();
        optionsCache.TryAdd(string.Empty, webAuthnOptions);
        Options = new(
            new OptionsFactory<WebAuthnOptions>(
                new List<IConfigureOptions<WebAuthnOptions>>(),
                new List<IPostConfigureOptions<WebAuthnOptions>>()),
            new List<IOptionsChangeTokenSource<WebAuthnOptions>>
            {
                new ConfigurationChangeTokenSource<WebAuthnOptions>(ConfigurationManager)
            },
            optionsCache);
        var safeJsonDeserializer = new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance);
        var digitalSignatureVerifier = new DefaultDigitalSignatureVerifier();
        var cborDeserializer = new DefaultCborDeserializer(NullLogger<DefaultCborDeserializer>.Instance);
        var asn1Deserializer = new DefaultAsn1Deserializer(NullLogger<DefaultAsn1Deserializer>.Instance);
        var tpmManufacturerVerifier = new DefaultTpmManufacturerVerifier();
        var coseDecoder = new DefaultCoseKeyDeserializer(cborDeserializer, NullLogger<DefaultCoseKeyDeserializer>.Instance);

        ContextFactory = new();
        var rpAddress = GetRelyingPartyAddress();
        var rpIdProvider = new FakeRelyingPartyIdProvider(rpAddress);
        var rpOriginProvider = new FakeRelyingPartyOriginProvider(rpAddress);
        var challengeGenerator = new DefaultChallengeGenerator();
        TimeProvider = new(GetCurrentTime());

        var publicKeyCredentialCreationOptionsEncoder = new DefaultPublicKeyCredentialCreationOptionsEncoder(
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorTransport>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<ResidentKeyRequirement>(),
            new DefaultEnumMemberAttributeSerializer<UserVerificationRequirement>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialHints>(),
            new DefaultEnumMemberAttributeSerializer<AttestationConveyancePreference>(),
            new DefaultEnumMemberAttributeSerializer<AttestationStatementFormat>());
        CredentialStorage = new();
        RegistrationCeremonyStorage = new();
        RegistrationCounters = new();
        var registrationResponseDecoder = new DefaultRegistrationResponseDecoder(
            new DefaultEnumMemberAttributeSerializer<AuthenticatorTransport>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>(),
            RegistrationCounters,
            NullLogger<DefaultRegistrationResponseDecoder>.Instance);
        var clientDataDecoder = new DefaultClientDataDecoder(
            safeJsonDeserializer,
            new DefaultEnumMemberAttributeSerializer<TokenBindingStatus>(),
            NullLogger<DefaultClientDataDecoder>.Instance);
        var attestationObjectDecoder = new DefaultAttestationObjectDecoder(
            cborDeserializer,
            new DefaultEnumMemberAttributeSerializer<AttestationStatementFormat>(),
            NullLogger<DefaultAttestationObjectDecoder>.Instance);
        DefaultFidoMetadataSearchService<FakeWebAuthnContext> metadataSearchService;
        using (var fakeFidoHttpClientProvider = new FakeFidoMetadataHttpClientProvider())
        {
            var metadataProvider = new DefaultFidoMetadataProvider(
                Options,
                safeJsonDeserializer,
                fakeFidoHttpClientProvider.Client,
                new FakeTimeProvider(DateTimeOffset.Parse("2026-10-17T17:20:02.0000000+00:00", CultureInfo.InvariantCulture)),
                new FakeFidoMetadataCounters(),
                NullLogger<DefaultFidoMetadataProvider>.Instance);
            var downloadMetadataResult = await metadataProvider.DownloadMetadataAsync(CancellationToken.None);
            if (downloadMetadataResult.HasError)
            {
                throw new InvalidOperationException("Can't get metadata to decode");
            }

            var decoder = new DefaultFidoMetadataDecoder(
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
                new FakeFidoMetadataCounters(),
                NullLogger<DefaultFidoMetadataDecoder>.Instance);
            var decodeMetadataResult = decoder.Decode(downloadMetadataResult.Ok);
            if (decodeMetadataResult.HasError)
            {
                throw new InvalidOperationException("Can't decode metadata");
            }

            MetadataBlob = decodeMetadataResult.Ok;
            MetadataStorage = new();
            FidoMetadataCounters = new();
            FidoMetadataSearchLogger = new();
            metadataSearchService = new(MetadataStorage, TimeProvider, FidoMetadataCounters, FidoMetadataSearchLogger);
            var metadataIngestService = new DefaultFidoMetadataIngestService(MetadataStorage);
            await metadataIngestService.UpsertAsync(
                MetadataBlob,
                CancellationToken.None);
        }

        var packedVerifier = new DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            digitalSignatureVerifier,
            asn1Deserializer,
            metadataSearchService,
            NullLogger<DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>>.Instance);
        var tpmVerifier = new DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            new DefaultTpmPubAreaDecoder(),
            new DefaultTpmCertInfoDecoder(),
            digitalSignatureVerifier,
            tpmManufacturerVerifier,
            asn1Deserializer,
            metadataSearchService,
            RegistrationCounters,
            NullLogger<DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>>.Instance);
        var androidKeyVerifier = new DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>(
            Options,
            TimeProvider,
            digitalSignatureVerifier,
            asn1Deserializer,
            metadataSearchService);
        var androidSafetyNetVerifier = new DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            safeJsonDeserializer,
            metadataSearchService,
            NullLogger<DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>>.Instance);
        var fidoU2FVerifier = new DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            asn1Deserializer,
            metadataSearchService,
            NullLogger<DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>>.Instance);
        var noneVerifier = new DefaultNoneAttestationStatementVerifier<FakeWebAuthnContext>();
        var appleAnonymousVerifier = new DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            asn1Deserializer,
            NullLogger<DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>>.Instance);
        var attestationStatementVerifier = new DefaultAttestationStatementVerifier<FakeWebAuthnContext>(
            packedVerifier,
            tpmVerifier,
            androidKeyVerifier,
            androidSafetyNetVerifier,
            fidoU2FVerifier,
            noneVerifier,
            appleAnonymousVerifier,
            NullLogger<DefaultAttestationStatementVerifier<FakeWebAuthnContext>>.Instance
        );
        var authenticatorDataDecoder = new DefaultAuthenticatorDataDecoder(coseDecoder, cborDeserializer, NullLogger<DefaultAuthenticatorDataDecoder>.Instance);
        var packedDecoder = new DefaultPackedAttestationStatementDecoder(RegistrationCounters, NullLogger<DefaultPackedAttestationStatementDecoder>.Instance);
        var tpmDecoder = new DefaultTpmAttestationStatementDecoder(RegistrationCounters, NullLogger<DefaultTpmAttestationStatementDecoder>.Instance);
        var androidKeyDecoder = new DefaultAndroidKeyAttestationStatementDecoder(NullLogger<DefaultAndroidKeyAttestationStatementDecoder>.Instance);
        var androidSafetyNetDecoder = new DefaultAndroidSafetyNetAttestationStatementDecoder(NullLogger<DefaultAndroidSafetyNetAttestationStatementDecoder>.Instance);
        var fidoU2FDecoder = new DefaultFidoU2FAttestationStatementDecoder(NullLogger<DefaultFidoU2FAttestationStatementDecoder>.Instance);
        var noneDecoder = new DefaultNoneAttestationStatementDecoder(NullLogger<DefaultNoneAttestationStatementDecoder>.Instance);
        var appleAnonymousDecoder = new DefaultAppleAnonymousAttestationStatementDecoder(NullLogger<DefaultAppleAnonymousAttestationStatementDecoder>.Instance);
        var attestationStatementDecoder = new DefaultAttestationStatementDecoder(
            androidKeyDecoder,
            androidSafetyNetDecoder,
            appleAnonymousDecoder,
            fidoU2FDecoder,
            noneDecoder,
            packedDecoder,
            tpmDecoder);
        var attestationTrustPathValidator = new DefaultAttestationTrustPathValidator(Options);
        RegistrationCeremonyService = new(
            Options,
            ContextFactory,
            rpIdProvider,
            rpOriginProvider,
            challengeGenerator,
            TimeProvider,
            publicKeyCredentialCreationOptionsEncoder,
            CredentialStorage,
            RegistrationCeremonyStorage,
            registrationResponseDecoder,
            clientDataDecoder,
            attestationObjectDecoder,
            authenticatorDataDecoder,
            attestationStatementDecoder,
            attestationStatementVerifier,
            attestationTrustPathValidator,
            RegistrationCounters,
            NullLogger<DefaultRegistrationCeremonyService<FakeWebAuthnContext>>.Instance);
    }

    [TearDown]
    public virtual void TearDownServices()
    {
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    [SuppressMessage("ReSharper", "ReturnTypeCanBeNotNullable")]
    protected virtual IEnumerable<KeyValuePair<string, string?>>? GetConfiguration()
    {
        yield break;
    }

    protected virtual void ConfigureWebAuthnOptions(WebAuthnOptions options)
    {
    }

    // the time the ceremonies run at; test vectors whose certificates expire override it with a fixed time
    protected virtual DateTimeOffset GetCurrentTime()
    {
        return DateTimeOffset.UtcNow;
    }

    // Replaces the metadata in use with a copy of the downloaded blob in which the entry for the aaguid has one more status report with the status,
    // as if the FIDO Metadata Service had published it (if the blob has no entry for the aaguid, an entry with only this status report is added).
    protected async Task UpsertMetadataWithStatusReportAsync(Guid aaguid, AuthenticatorStatus status)
    {
        var statusReport = new StatusReport(status, null, null, null, null, null, null, null, null, null, null, null, null, null);
        var entries = MetadataBlob.Entries.ToList();
        var index = entries.FindIndex(x => x.Aaguid == aaguid);
        if (index >= 0)
        {
            var entry = entries[index];
            entries[index] = new(
                entry.Aaid,
                entry.Aaguid,
                entry.AttestationCertificateKeyIdentifiers,
                entry.MetadataStatement,
                entry.BiometricStatusReports,
                entry.StatusReports.Append(statusReport).ToArray(),
                entry.TimeOfLastStatusChange,
                entry.RogueListUrl,
                entry.RogueListHash);
        }
        else
        {
            entries.Add(new(null, aaguid, null, null, null, new[] { statusReport }, DateTimeOffset.UnixEpoch, null, null));
        }

        await MetadataStorage.UpsertAsync(
            new(MetadataBlob.LegalHeader, MetadataBlob.No, MetadataBlob.NextUpdate, entries.ToArray()),
            CancellationToken.None);
    }

    protected abstract Uri GetRelyingPartyAddress();
    protected DefaultRegistrationCeremonyService<FakeWebAuthnContext> RegistrationCeremonyService { get; set; } = null!;
    protected OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    protected ConfigurationManager ConfigurationManager { get; set; } = null!;
    protected FakeCredentialStorage CredentialStorage { get; set; } = null!;
    protected FakeRegistrationCeremonyStorage RegistrationCeremonyStorage { get; set; } = null!;
    protected FakeTimeProvider TimeProvider { get; set; } = null!;
    protected FakeWebAuthnContextFactory ContextFactory { get; set; } = null!;
    protected DefaultRegistrationCeremonyCounters RegistrationCounters { get; set; } = null!;
    protected MetadataBlobPayload MetadataBlob { get; set; } = null!;
    protected DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext> MetadataStorage { get; set; } = null!;
    protected FakeFidoMetadataCounters FidoMetadataCounters { get; set; } = null!;
    protected FakeLogger<DefaultFidoMetadataSearchService<FakeWebAuthnContext>> FidoMetadataSearchLogger { get; set; } = null!;
}
