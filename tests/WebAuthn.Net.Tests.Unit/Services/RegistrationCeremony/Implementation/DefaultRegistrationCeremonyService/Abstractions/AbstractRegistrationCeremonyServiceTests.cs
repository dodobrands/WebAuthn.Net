using System;
using System.Collections.Generic;
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
using WebAuthn.Net.Services.Cryptography.Cose.Implementation;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataService;
using WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
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
        var digitalSignatureVerifier = new DefaultDigitalSignatureVerifier();
        var cborDecoder = new DefaultCborDecoder(NullLogger<DefaultCborDecoder>.Instance);
        var asn1Decoder = new DefaultAsn1Decoder();
        var tpmManufacturerVerifier = new DefaultTpmManufacturerVerifier();
        var coseDecoder = new DefaultCoseKeyDecoder(cborDecoder, NullLogger<DefaultCoseKeyDecoder>.Instance);

        var fakeContextFactory = new FakeWebAuthnContextFactory();
        var rpAddress = GetRelyingPartyAddress();
        var rpIdProvider = new FakeRelyingPartyIdProvider(rpAddress);
        var rpOriginProvider = new FakeRelyingPartyOriginProvider(rpAddress);
        var challengeGenerator = new DefaultChallengeGenerator();
        TimeProvider = new(DateTimeOffset.UtcNow);

        var publicKeyCredentialCreationOptionsEncoder = new DefaultPublicKeyCredentialCreationOptionsEncoder();
        FakeCredentialStorage credentialStorage = new();
        RegistrationCeremonyStorage = new();
        var registrationResponseDecoder = new DefaultRegistrationResponseDecoder();
        var clientDataDecoder = new DefaultClientDataDecoder(NullLogger<DefaultClientDataDecoder>.Instance);
        var attestationObjectDecoder = new DefaultAttestationObjectDecoder(
            cborDecoder,
            NullLogger<DefaultAttestationObjectDecoder>.Instance);
        DefaultFidoAttestationCertificateInspector<FakeWebAuthnContext> attestationCertificateInspector;
        using (var fakeFidoHttpClientProvider = new FakeFidoMetadataHttpClientProvider())
        {
            var metadataProvider = new DefaultFidoMetadataProvider(
                fakeFidoHttpClientProvider.Client,
                new FakeTimeProvider(DateTimeOffset.Parse("2023-10-20T16:36:38Z", CultureInfo.InvariantCulture)));
            var downloadMetadataResult = await metadataProvider.DownloadMetadataAsync(CancellationToken.None);
            if (downloadMetadataResult.HasError)
            {
                throw new InvalidOperationException("Can't get metadata to decode");
            }

            var decoder = new DefaultFidoMetadataDecoder();
            var decodeMetadataResult = decoder.Decode(downloadMetadataResult.Ok);
            if (decodeMetadataResult.HasError)
            {
                throw new InvalidOperationException("Can't decode metadata");
            }

            var storage = new DefaultInMemoryFidoMetadataStorage<FakeWebAuthnContext>();
            var metadataService = new DefaultFidoMetadataService<FakeWebAuthnContext>(storage);
            await metadataService.UpsertAsync(
                decodeMetadataResult.Ok,
                CancellationToken.None);
            attestationCertificateInspector = new(
                metadataService,
                asn1Decoder);
        }

        var packedVerifier = new DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            digitalSignatureVerifier,
            asn1Decoder,
            attestationCertificateInspector);
        var tpmVerifier = new DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            digitalSignatureVerifier,
            tpmManufacturerVerifier,
            asn1Decoder,
            attestationCertificateInspector);
        var androidKeyVerifier = new DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>(
            Options,
            TimeProvider,
            digitalSignatureVerifier,
            asn1Decoder,
            attestationCertificateInspector);
        var androidSafetyNetVerifier = new DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>(TimeProvider, attestationCertificateInspector);
        var fidoU2FVerifier = new DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>(TimeProvider, asn1Decoder, attestationCertificateInspector);
        var noneVerifier = new DefaultNoneAttestationStatementVerifier<FakeWebAuthnContext>();
        var appleAnonymousVerifier = new DefaultAppleAnonymousAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            asn1Decoder);
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
        var authenticatorDataDecoder = new DefaultAuthenticatorDataDecoder(coseDecoder, NullLogger<DefaultAuthenticatorDataDecoder>.Instance);
        var packedDecoder = new DefaultPackedAttestationStatementDecoder(NullLogger<DefaultPackedAttestationStatementDecoder>.Instance);
        var tpmDecoder = new DefaultTpmAttestationStatementDecoder(NullLogger<DefaultTpmAttestationStatementDecoder>.Instance);
        var androidKeyDecoder = new DefaultAndroidKeyAttestationStatementDecoder(NullLogger<DefaultAndroidKeyAttestationStatementDecoder>.Instance);
        var androidSafetyNetDecoder = new DefaultAndroidSafetyNetAttestationStatementDecoder(NullLogger<DefaultAndroidSafetyNetAttestationStatementDecoder>.Instance);
        var fidoU2FDecoder = new DefaultFidoU2FAttestationStatementDecoder(NullLogger<DefaultFidoU2FAttestationStatementDecoder>.Instance);
        var noneDecoder = new DefaultNoneAttestationStatementDecoder(NullLogger<DefaultNoneAttestationStatementDecoder>.Instance);
        var appleAnonymousDecoder = new DefaultAppleAnonymousAttestationStatementDecoder(NullLogger<DefaultAppleAnonymousAttestationStatementDecoder>.Instance);
        var attestationStatementDecoder = new DefaultAttestationStatementDecoder(
            packedDecoder,
            tpmDecoder,
            androidKeyDecoder,
            androidSafetyNetDecoder,
            fidoU2FDecoder,
            noneDecoder,
            appleAnonymousDecoder);
        var attestationTrustPathValidator = new DefaultAttestationTrustPathValidator(Options);
        RegistrationCeremonyService = new(
            Options,
            fakeContextFactory,
            rpIdProvider,
            rpOriginProvider,
            challengeGenerator,
            TimeProvider,
            publicKeyCredentialCreationOptionsEncoder,
            credentialStorage,
            RegistrationCeremonyStorage,
            registrationResponseDecoder,
            clientDataDecoder,
            attestationObjectDecoder,
            authenticatorDataDecoder,
            attestationStatementDecoder,
            attestationStatementVerifier,
            attestationTrustPathValidator,
            NullLogger<DefaultRegistrationCeremonyService<FakeWebAuthnContext>>.Instance);
    }

    [TearDown]
    public virtual void TearDownServices()
    {
        Options.Dispose();
        ConfigurationManager.Dispose();
    }

    protected virtual IEnumerable<KeyValuePair<string, string>> GetConfiguration()
    {
        yield break;
    }

    protected abstract Uri GetRelyingPartyAddress();
    protected DefaultRegistrationCeremonyService<FakeWebAuthnContext> RegistrationCeremonyService { get; set; } = null!;
    protected OptionsMonitor<WebAuthnOptions> Options { get; set; } = null!;
    protected ConfigurationManager ConfigurationManager { get; set; } = null!;
    protected FakeRegistrationCeremonyStorage RegistrationCeremonyStorage { get; set; } = null!;
    protected FakeTimeProvider TimeProvider { get; set; } = null!;
}
