using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
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
using WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder.Implementation;
using WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder.Implementation;
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
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Metrics.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Services.Serialization.Cose.Implementation;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.DefaultAuthenticationCeremonyService.Abstractions;

[TestFixture]
public abstract class AbstractAuthenticationCeremonyServiceTests
{
    [SetUp]
    public virtual async Task SetupServices()
    {
        ConfigurationManager = new();
        ConfigurationManager.AddInMemoryCollection(GetConfiguration());
        var webAuthnOptions = ConfigurationManager.Get<WebAuthnOptions>() ?? new WebAuthnOptions();
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
        TimeProvider = new(DateTimeOffset.UtcNow);

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
        AuthenticationCeremonyStorage = new();

        var registrationResponseDecoder = new DefaultRegistrationResponseDecoder(
            new DefaultEnumMemberAttributeSerializer<AuthenticatorTransport>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>());
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
                new FakeTimeProvider(DateTimeOffset.Parse("2023-10-20T16:36:38Z", CultureInfo.InvariantCulture)));
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
                new DefaultEnumMemberAttributeSerializer<TransactionConfirmationDisplayType>());
            var decodeMetadataResult = decoder.Decode(downloadMetadataResult.Ok);
            if (decodeMetadataResult.HasError)
            {
                throw new InvalidOperationException("Can't decode metadata");
            }

            var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
            metadataSearchService = new(storage, TimeProvider);
            var metadataIngestService = new DefaultFidoMetadataIngestService(storage);
            await metadataIngestService.UpsertAsync(
                decodeMetadataResult.Ok,
                CancellationToken.None);
        }

        var packedVerifier = new DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            digitalSignatureVerifier,
            asn1Deserializer,
            metadataSearchService);
        var tpmVerifier = new DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            new DefaultTpmPubAreaDecoder(),
            new DefaultTpmCertInfoDecoder(),
            digitalSignatureVerifier,
            tpmManufacturerVerifier,
            asn1Deserializer,
            metadataSearchService);
        var androidKeyVerifier = new DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>(
            Options,
            TimeProvider,
            digitalSignatureVerifier,
            asn1Deserializer,
            metadataSearchService);
        var androidSafetyNetVerifier = new DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            safeJsonDeserializer,
            metadataSearchService);
        var fidoU2FVerifier = new DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            asn1Deserializer,
            metadataSearchService);
        var noneVerifier = new DefaultNoneAttestationStatementVerifier<FakeWebAuthnContext>();
        var appleAnonymousVerifier = new DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            asn1Deserializer);
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
        var packedDecoder = new DefaultPackedAttestationStatementDecoder(NullLogger<DefaultPackedAttestationStatementDecoder>.Instance);
        var tpmDecoder = new DefaultTpmAttestationStatementDecoder(NullLogger<DefaultTpmAttestationStatementDecoder>.Instance);
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

        var publicKeyCredentialRequestOptionsEncoder = new DefaultPublicKeyCredentialRequestOptionsEncoder(
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>(),
            new DefaultEnumMemberAttributeSerializer<AuthenticatorTransport>(),
            new DefaultEnumMemberAttributeSerializer<UserVerificationRequirement>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialHints>(),
            new DefaultEnumMemberAttributeSerializer<AttestationConveyancePreference>(),
            new DefaultEnumMemberAttributeSerializer<AttestationStatementFormat>());
        var authenticationResponseDecoder = new DefaultAuthenticationResponseDecoder(
            new DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>(),
            new DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>());

        RegistrationCounters = new();
        AuthenticationCounters = new();

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
        AuthenticationCeremonyService = new(
            Options,
            ContextFactory,
            rpIdProvider,
            rpOriginProvider,
            challengeGenerator,
            TimeProvider,
            publicKeyCredentialRequestOptionsEncoder,
            CredentialStorage,
            AuthenticationCeremonyStorage,
            authenticationResponseDecoder,
            clientDataDecoder,
            attestationObjectDecoder,
            authenticatorDataDecoder,
            attestationStatementDecoder,
            attestationStatementVerifier,
            attestationTrustPathValidator,
            digitalSignatureVerifier,
            AuthenticationCounters,
            NullLogger<DefaultAuthenticationCeremonyService<FakeWebAuthnContext>>.Instance);
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

    protected abstract Uri GetRelyingPartyAddress();
    protected DefaultRegistrationCeremonyService<FakeWebAuthnContext> RegistrationCeremonyService { get; set; } = null!;
    protected DefaultAuthenticationCeremonyService<FakeWebAuthnContext> AuthenticationCeremonyService { get; set; } = null!;
    protected OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    protected ConfigurationManager ConfigurationManager { get; set; } = null!;
    protected FakeRegistrationCeremonyStorage RegistrationCeremonyStorage { get; set; } = null!;
    protected FakeAuthenticationCeremonyStorage AuthenticationCeremonyStorage { get; set; } = null!;
    protected FakeTimeProvider TimeProvider { get; set; } = null!;
    protected FakeCredentialStorage CredentialStorage { get; set; } = null!;
    protected FakeWebAuthnContextFactory ContextFactory { get; set; } = null!;
    protected DefaultRegistrationCeremonyCounters RegistrationCounters { get; set; } = null!;
    protected DefaultAuthenticationCeremonyCounters AuthenticationCounters { get; set; } = null!;
}
