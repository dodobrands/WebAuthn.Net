using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Services.Cryptography.Cose.Implementation;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Implementation.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.AndroidKey;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.AndroidSafetyNet;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Apple;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.FidoU2F;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.None;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Packed;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AuthenticatorDataDecoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.ChallengeGenerator.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.ClientDataDecoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.OptionsEncoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.DefaultRegistrationCeremonyService.Abstractions;

[TestFixture]
public abstract class AbstractRegistrationCeremonyServiceTests
{
    [SetUp]
    public virtual void SetupServices()
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
        var publicKeyCredentialCreationOptionsEncoder = new DefaultPublicKeyCredentialCreationOptionsEncoder<FakeWebAuthnContext>();
        Storage = new();
        var registrationResponseDecoder = new DefaultRegistrationResponseDecoder<FakeWebAuthnContext>();
        var clientDataDecoder = new DefaultClientDataDecoder<FakeWebAuthnContext>(NullLogger<DefaultClientDataDecoder<FakeWebAuthnContext>>.Instance);
        var attestationObjectDecoder = new DefaultAttestationObjectDecoder<FakeWebAuthnContext>(
            cborDecoder,
            NullLogger<DefaultAttestationObjectDecoder<FakeWebAuthnContext>>.Instance);

        var packedVerifier = new DefaultPackedAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            digitalSignatureVerifier,
            asn1Decoder);
        var tpmVerifier = new DefaultTpmAttestationStatementVerifier<FakeWebAuthnContext>(
            TimeProvider,
            digitalSignatureVerifier,
            tpmManufacturerVerifier,
            asn1Decoder);
        var androidKeyVerifier = new DefaultAndroidKeyAttestationStatementVerifier<FakeWebAuthnContext>(
            Options,
            TimeProvider,
            digitalSignatureVerifier,
            asn1Decoder);
        var androidSafetyNetVerifier = new DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>(TimeProvider);
        var fidoU2FVerifier = new DefaultFidoU2FAttestationStatementVerifier<FakeWebAuthnContext>(TimeProvider);
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

        RegistrationCeremonyService = new(
            Options,
            fakeContextFactory,
            rpIdProvider,
            rpOriginProvider,
            challengeGenerator,
            TimeProvider,
            publicKeyCredentialCreationOptionsEncoder,
            Storage,
            registrationResponseDecoder,
            clientDataDecoder,
            attestationObjectDecoder,
            attestationStatementVerifier,
            authenticatorDataDecoder,
            attestationStatementDecoder, NullLogger<DefaultRegistrationCeremonyService<FakeWebAuthnContext>>.Instance
        );
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
    protected FakeTimeProvider TimeProvider { get; set; } = null!;
    protected FakeOperationalStorage Storage { get; set; } = null!;
}
