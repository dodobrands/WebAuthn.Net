using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder;
using WebAuthn.Net.Services.AuthenticationCeremony.Services.AuthenticationResponseDecoder.Implementation;
using WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder;
using WebAuthn.Net.Services.AuthenticationCeremony.Services.PublicKeyCredentialRequestOptionsEncoder.Implementation;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidKey;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Apple;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.FidoU2F;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.None;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Packed;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Apple;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.FidoU2F;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.None;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Packed;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator;
using WebAuthn.Net.Services.Common.AttestationTrustPathValidator.Implementation;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;
using WebAuthn.Net.Services.Common.ChallengeGenerator;
using WebAuthn.Net.Services.Common.ChallengeGenerator.Implementation;
using WebAuthn.Net.Services.Common.ClientDataDecoder;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Implementation;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.Cryptography.Cose;
using WebAuthn.Net.Services.Cryptography.Cose.Implementation;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Providers.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder;
using WebAuthn.Net.Services.RegistrationCeremony.Services.PublicKeyCredentialCreationOptionsEncoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder;
using WebAuthn.Net.Services.RegistrationCeremony.Services.RegistrationResponseDecoder.Implementation;
using WebAuthn.Net.Services.Serialization.Asn1;
using WebAuthn.Net.Services.Serialization.Asn1.Implementation;
using WebAuthn.Net.Services.Serialization.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;
using WebAuthn.Net.Storage.RegistrationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

namespace WebAuthn.Net.Configuration.DependencyInjection;

public static class WebAuthnBuilderExtensions
{
    public static IWebAuthnBuilder<TContext> AddCoreServices<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<WebAuthnOptions>? configure = null,
        Action<IHttpClientBuilder>? configureFidoHttpClientBuilder = null,
        Action<FidoMetadataBackgroundIngestHostedServiceOptions>? configureBackgroundIngest = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions<WebAuthnOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.AddAuthenticationServices()
            .AddCommonServices()
            .AddCryptographyServices()
            .AddFidoMetadataServices()
            .AddFidoMetadataHttpClient(configureFidoHttpClientBuilder)
            .AddFidoMetadataBackgroundIngest(configureBackgroundIngest)
            .AddProviders()
            .AddRegistrationCeremonyServices()
            .AddSerializationServices();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddAuthenticationServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IAuthenticationCeremonyService, DefaultAuthenticationCeremonyService<TContext>>();
        builder.Services.TryAddSingleton<IPublicKeyCredentialRequestOptionsEncoder, DefaultPublicKeyCredentialRequestOptionsEncoder>();
        builder.Services.TryAddSingleton<IAuthenticationResponseDecoder, DefaultAuthenticationResponseDecoder>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddCommonServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);

        // -- AttestationObjectDecoder --
        builder.Services.TryAddSingleton<IAttestationObjectDecoder, DefaultAttestationObjectDecoder>();
        // ------------------------------

        // -- AttestationStatementDecoder --
        builder.Services.TryAddSingleton<IAttestationStatementDecoder, DefaultAttestationStatementDecoder>();
        builder.Services.TryAddSingleton<IAndroidKeyAttestationStatementDecoder, DefaultAndroidKeyAttestationStatementDecoder>();
        builder.Services.TryAddSingleton<IAndroidSafetyNetAttestationStatementDecoder, DefaultAndroidSafetyNetAttestationStatementDecoder>();
        builder.Services.TryAddSingleton<IAppleAnonymousAttestationStatementDecoder, DefaultAppleAnonymousAttestationStatementDecoder>();
        builder.Services.TryAddSingleton<IFidoU2FAttestationStatementDecoder, DefaultFidoU2FAttestationStatementDecoder>();
        builder.Services.TryAddSingleton<INoneAttestationStatementDecoder, DefaultNoneAttestationStatementDecoder>();
        builder.Services.TryAddSingleton<IPackedAttestationStatementDecoder, DefaultPackedAttestationStatementDecoder>();
        builder.Services.TryAddSingleton<ITpmAttestationStatementDecoder, DefaultTpmAttestationStatementDecoder>();
        // ---------------------------------

        // -- AttestationStatementVerifier --
        builder.Services.TryAddSingleton<IAttestationStatementVerifier<TContext>, DefaultAttestationStatementVerifier<TContext>>();
        builder.Services.TryAddSingleton<IFidoAttestationCertificateInspector<TContext>, DefaultFidoAttestationCertificateInspector<TContext>>();
        // AndroidKey
        builder.Services.TryAddSingleton<IAndroidKeyAttestationStatementVerifier<TContext>, DefaultAndroidKeyAttestationStatementVerifier<TContext>>();
        // AndroidSafetyNet
        builder.Services.TryAddSingleton<IAndroidSafetyNetAttestationStatementVerifier<TContext>, DefaultAndroidSafetyNetAttestationStatementVerifier<TContext>>();
        // Apple
        builder.Services.TryAddSingleton<IAppleAnonymousAttestationStatementVerifier<TContext>, DefaultAppleAnonymousAttestationStatementVerifier<TContext>>();
        // FidoU2F
        builder.Services.TryAddSingleton<IFidoU2FAttestationStatementVerifier<TContext>, DefaultFidoU2FAttestationStatementVerifier<TContext>>();
        // None
        builder.Services.TryAddSingleton<INoneAttestationStatementVerifier<TContext>, DefaultNoneAttestationStatementVerifier<TContext>>();
        // Packed
        builder.Services.TryAddSingleton<IPackedAttestationStatementVerifier<TContext>, DefaultPackedAttestationStatementVerifier<TContext>>();
        // Tpm
        builder.Services.TryAddSingleton<ITpmAttestationStatementVerifier<TContext>, DefaultTpmAttestationStatementVerifier<TContext>>();
        builder.Services.TryAddSingleton<ITpmManufacturerVerifier, DefaultTpmManufacturerVerifier>();
        // ----------------------------------

        // -- AttestationTrustPathValidator --
        builder.Services.TryAddSingleton<IAttestationTrustPathValidator, DefaultAttestationTrustPathValidator>();
        // -----------------------------------

        // -- AuthenticatorDataDecoder --
        builder.Services.TryAddSingleton<IAuthenticatorDataDecoder, DefaultAuthenticatorDataDecoder>();
        // ------------------------------

        // -- ChallengeGenerator --
        builder.Services.TryAddSingleton<IChallengeGenerator, DefaultChallengeGenerator>();
        // ------------------------

        // -- ChallengeGenerator --
        builder.Services.TryAddSingleton<IClientDataDecoder, DefaultClientDataDecoder>();
        // ------------------------

        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddCryptographyServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<ICoseKeyDecoder, DefaultCoseKeyDecoder>();
        builder.Services.TryAddSingleton<IDigitalSignatureVerifier, DefaultDigitalSignatureVerifier>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddFidoMetadataServices<TContext>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IFidoMetadataDecoder, DefaultFidoMetadataDecoder>();
        builder.Services.TryAddSingleton<IFidoMetadataIngestService, DefaultFidoMetadataIngestService>();
        builder.Services.TryAddSingleton<IFidoMetadataProvider, DefaultFidoMetadataProvider>();
        builder.Services.TryAddSingleton<IFidoMetadataSearchService<TContext>, DefaultFidoMetadataSearchService<TContext>>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddFidoMetadataHttpClient<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<IHttpClientBuilder>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        var httpClientBuilder = builder.Services.AddHttpClient<IFidoMetadataHttpClient, DefaultFidoMetadataHttpClient>();
        if (configure is not null)
        {
            configure(httpClientBuilder);
        }

        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddFidoMetadataBackgroundIngest<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<FidoMetadataBackgroundIngestHostedServiceOptions>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions<FidoMetadataBackgroundIngestHostedServiceOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.Services.AddHostedService<FidoMetadataBackgroundIngestHostedService>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddProviders<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRelyingPartyIdProvider, DefaultRelyingPartyIdProvider>();
        builder.Services.TryAddSingleton<IRelyingPartyOriginProvider, DefaultRelyingPartyOriginProvider>();
        builder.Services.TryAddSingleton<ITimeProvider, DefaultTimeProvider>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddRegistrationCeremonyServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRegistrationCeremonyService, DefaultRegistrationCeremonyService<TContext>>();
        builder.Services.TryAddSingleton<IRegistrationResponseDecoder, DefaultRegistrationResponseDecoder>();
        builder.Services.TryAddSingleton<IPublicKeyCredentialCreationOptionsEncoder, DefaultPublicKeyCredentialCreationOptionsEncoder>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddSerializationServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IAsn1Decoder, DefaultAsn1Decoder>();
        builder.Services.TryAddSingleton<ICborDecoder, DefaultCborDecoder>();
        return builder;
    }

    /*********************************/
    /******** CONTEXT FACTORY ********/
    /*********************************/
    public static IWebAuthnBuilder<TContext> AddContextFactory<TContext, TContextFactoryImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TContextFactoryImpl : class, IWebAuthnContextFactory<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IWebAuthnContextFactory<TContext>, TContextFactoryImpl>();
        return builder;
    }

    /********************************/
    /*********** STORAGES ***********/
    /********************************/
    // Default
    public static IWebAuthnBuilder<TContext> AddDefaultStorages<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configureRegistration = null,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configureAuthentication = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder
            .AddDefaultRegistrationCeremonyStorage(configureRegistration)
            .AddDefaultAuthenticationCeremonyStorage(configureAuthentication)
            .AddDefaultFidoMetadataStorage();
    }

    public static IWebAuthnBuilder<TContext> AddDefaultRegistrationCeremonyStorage<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions<DefaultCookieRegistrationCeremonyStorageOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.Services.AddDataProtection();
        return builder.AddRegistrationCeremonyStorage<TContext, DefaultCookieRegistrationCeremonyStorage<TContext>>();
    }

    public static IWebAuthnBuilder<TContext> AddDefaultAuthenticationCeremonyStorage<TContext>(
        this IWebAuthnBuilder<TContext> builder,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions<DefaultCookieAuthenticationCeremonyStorageOptions>();
        if (configure is not null)
        {
            builder.Services.Configure(configure);
        }

        builder.Services.AddDataProtection();
        return builder.AddAuthenticationCeremonyStorage<TContext, DefaultCookieAuthenticationCeremonyStorage<TContext>>();
    }

    public static IWebAuthnBuilder<TContext> AddDefaultFidoMetadataStorage<TContext>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        var storage = new DefaultInMemoryFidoMetadataStorage<TContext>();
        builder.Services.TryAddSingleton<IFidoMetadataIngestStorage>(storage);
        builder.Services.TryAddSingleton<IFidoMetadataSearchStorage<TContext>>(storage);
        return builder;
    }

    // Non-default
    public static IWebAuthnBuilder<TContext> AddRegistrationCeremonyStorage<TContext, TRegistrationCeremonyStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TRegistrationCeremonyStorageImpl : class, IRegistrationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRegistrationCeremonyStorage<TContext>, TRegistrationCeremonyStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddAuthenticationCeremonyStorage<TContext, TAuthenticationCeremonyStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TAuthenticationCeremonyStorageImpl : class, IAuthenticationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IAuthenticationCeremonyStorage<TContext>, TAuthenticationCeremonyStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddFidoMetadataSearchStorage<TContext, TFidoMetadataSearchStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TFidoMetadataSearchStorageImpl : class, IFidoMetadataSearchStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IFidoMetadataSearchStorage<TContext>, TFidoMetadataSearchStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddFidoMetadataIngestStorage<TContext, TFidoMetadataIngestStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TFidoMetadataIngestStorageImpl : class, IFidoMetadataIngestStorage
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IFidoMetadataIngestStorage, TFidoMetadataIngestStorageImpl>();
        return builder;
    }

    public static IWebAuthnBuilder<TContext> AddCredentialStorage<TContext, TCredentialStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TCredentialStorageImpl : class, ICredentialStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<ICredentialStorage<TContext>, TCredentialStorageImpl>();
        return builder;
    }
}
