using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
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
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models.Enums;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.Cryptography.Sign;
using WebAuthn.Net.Services.Cryptography.Sign.Implementation;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataIngestService;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Metrics.Implementation;
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
using WebAuthn.Net.Services.Serialization.Cose;
using WebAuthn.Net.Services.Serialization.Cose.Implementation;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using WebAuthn.Net.Storage.AuthenticationCeremony;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Implementation;
using WebAuthn.Net.Storage.RegistrationCeremony;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

namespace WebAuthn.Net.Configuration.DependencyInjection;

/// <summary>
///     Extension methods to <see cref="IWebAuthnBuilder{TContext}" /> for configuring WebAuthn.Net.
/// </summary>
public static class WebAuthnBuilderExtensions
{
    /// <summary>
    ///     Adds the essential services to <see cref="IServiceCollection" />, which are necessary for WebAuthn.Net
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <param name="configure">An optional delegate for configuring global WebAuthn.Net options.</param>
    /// <param name="configureFidoHttpClientBuilder">
    ///     An optional delegate for configuring the HttpClient that will be used to access the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>. Here you can add retries using
    ///     <a href="https://github.com/App-vNext/Polly">Polly</a>, set timeouts, add your own DelegatingHandlers, or otherwise customize the behavior of HttpClient.
    /// </param>
    /// <param name="configureBackgroundIngest">An optional delegate for configuring the behavior of background data ingest from <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

        builder.AddAuthenticationCeremonyServices()
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

    /// <summary>
    ///     Adds a set of services directly responsible for the authentication ceremony to DI.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddAuthenticationCeremonyServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IAuthenticationCeremonyService, DefaultAuthenticationCeremonyService<TContext>>();
        builder.Services.TryAddSingleton<IPublicKeyCredentialRequestOptionsEncoder, DefaultPublicKeyCredentialRequestOptionsEncoder>();
        builder.Services.TryAddSingleton<IAuthenticationResponseDecoder, DefaultAuthenticationResponseDecoder>();
        return builder;
    }

    /// <summary>
    ///     Adds a set of common services to DI that are used both in the registration ceremony and in the authentication ceremony.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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
        builder.Services.TryAddSingleton<ITpmPubAreaDecoder, DefaultTpmPubAreaDecoder>();
        builder.Services.TryAddSingleton<ITpmCertInfoDecoder, DefaultTpmCertInfoDecoder>();
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

        // -- Metrics --
        builder.Services.TryAddSingleton<IAuthenticationCeremonyCounters, DefaultAuthenticationCeremonyCounters>();
        builder.Services.TryAddSingleton<IRegistrationCeremonyCounters, DefaultRegistrationCeremonyCounters>();
        // ---------------------

        return builder;
    }

    /// <summary>
    ///     Adds a set of common services to DI responsible for handling cryptography.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddCryptographyServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IDigitalSignatureVerifier, DefaultDigitalSignatureVerifier>();
        return builder;
    }

    /// <summary>
    ///     Adds a set of services to DI responsible for working with <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds an HttpClient to DI, responsible for interacting with <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <param name="configure">
    ///     An optional delegate for configuring the HttpClient that will be used to access the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>. Here you can add retries using <a href="https://github.com/App-vNext/Polly">Polly</a>, set timeouts,
    ///     add your own DelegatingHandlers, or otherwise customize the behavior of HttpClient.
    /// </param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds a set of services to DI responsible for background data ingest from <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <param name="configure">An optional delegate for configuring the behavior of background data ingest from <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds a set of provider services to DI that provide data about the environment in which WebAuthn operations are processed - the current time, rpId, etc.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddProviders<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRelyingPartyIdProvider, DefaultRelyingPartyIdProvider>();
        builder.Services.TryAddSingleton<IRelyingPartyOriginProvider, DefaultRelyingPartyOriginProvider>();
        builder.Services.TryAddSingleton<ITimeProvider, DefaultTimeProvider>();
        return builder;
    }

    /// <summary>
    ///     Adds a set of services to DI responsible for the registration ceremony.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddRegistrationCeremonyServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRegistrationCeremonyService, DefaultRegistrationCeremonyService<TContext>>();
        builder.Services.TryAddSingleton<IRegistrationResponseDecoder, DefaultRegistrationResponseDecoder>();
        builder.Services.TryAddSingleton<IPublicKeyCredentialCreationOptionsEncoder, DefaultPublicKeyCredentialCreationOptionsEncoder>();
        return builder;
    }

    /// <summary>
    ///     Adds a common set of services to DI responsible for serialization and deserialization.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddSerializationServices<TContext>(this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<ICoseKeyDeserializer, DefaultCoseKeyDeserializer>();
        builder.Services.TryAddSingleton<IAsn1Deserializer, DefaultAsn1Deserializer>();
        builder.Services.TryAddSingleton<ICborDeserializer, DefaultCborDeserializer>();
        builder.Services.TryAddSingleton<ISafeJsonSerializer, DefaultSafeJsonSerializer>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<AttestationStatementFormat>, DefaultEnumMemberAttributeSerializer<AttestationStatementFormat>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<TokenBindingStatus>, DefaultEnumMemberAttributeSerializer<TokenBindingStatus>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<UserVerificationMethod>, DefaultEnumMemberAttributeSerializer<UserVerificationMethod>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<ProtocolFamily>, DefaultEnumMemberAttributeSerializer<ProtocolFamily>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<AuthenticationAlgorithm>, DefaultEnumMemberAttributeSerializer<AuthenticationAlgorithm>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<PublicKeyRepresentationFormat>, DefaultEnumMemberAttributeSerializer<PublicKeyRepresentationFormat>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<AuthenticatorAttestationType>, DefaultEnumMemberAttributeSerializer<AuthenticatorAttestationType>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<KeyProtectionType>, DefaultEnumMemberAttributeSerializer<KeyProtectionType>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<MatcherProtectionType>, DefaultEnumMemberAttributeSerializer<MatcherProtectionType>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<AuthenticatorAttachmentHint>, DefaultEnumMemberAttributeSerializer<AuthenticatorAttachmentHint>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<TransactionConfirmationDisplayType>, DefaultEnumMemberAttributeSerializer<TransactionConfirmationDisplayType>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<AuthenticatorAttachment>, DefaultEnumMemberAttributeSerializer<AuthenticatorAttachment>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<PublicKeyCredentialType>, DefaultEnumMemberAttributeSerializer<PublicKeyCredentialType>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<AuthenticatorTransport>, DefaultEnumMemberAttributeSerializer<AuthenticatorTransport>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<UserVerificationRequirement>, DefaultEnumMemberAttributeSerializer<UserVerificationRequirement>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<PublicKeyCredentialHints>, DefaultEnumMemberAttributeSerializer<PublicKeyCredentialHints>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<AttestationConveyancePreference>, DefaultEnumMemberAttributeSerializer<AttestationConveyancePreference>>();
        builder.Services.TryAddSingleton<IEnumMemberAttributeSerializer<ResidentKeyRequirement>, DefaultEnumMemberAttributeSerializer<ResidentKeyRequirement>>();
        return builder;
    }


    /*********************************/
    /******** CONTEXT FACTORY ********/
    /*********************************/

    /// <summary>
    ///     Adds a factory to DI, which will create objects of type <typeparamref name="TContext" /> before performing any operations, so that any WebAuthn operations are carried out in the specified context.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <typeparam name="TContextFactoryImpl">A class implementing the <see cref="IWebAuthnContextFactory{TContext}" /> interface.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds standard implementations of several storages to DI.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <param name="configureRegistration">An optional delegate for configuring the behavior of the storage responsible for storing registration ceremony data.</param>
    /// <param name="configureAuthentication">An optional delegate for configuring the behavior of the storage responsible for storing authentication ceremony data.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds a standard implementation of storage to DI, responsible for handling the registration ceremony.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <param name="configure">An optional delegate for configuring the behavior of the storage responsible for storing registration ceremony data.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds a standard implementation of storage to DI, responsible for handling the authentication ceremony.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <param name="configure">An optional delegate for configuring the behavior of the storage responsible for storing authentication ceremony data.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds a standard implementation of storage to DI, responsible for storing FIDO metadata.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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

    /// <summary>
    ///     Adds an implementation of storage to DI, responsible for storing registration ceremony data.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <typeparam name="TRegistrationCeremonyStorageImpl">A class implementing the <see cref="IRegistrationCeremonyStorage{TContext}" /> interface.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddRegistrationCeremonyStorage<TContext, TRegistrationCeremonyStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TRegistrationCeremonyStorageImpl : class, IRegistrationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IRegistrationCeremonyStorage<TContext>, TRegistrationCeremonyStorageImpl>();
        return builder;
    }

    /// <summary>
    ///     Adds an implementation of storage to DI, responsible for storing authentication ceremony data.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <typeparam name="TAuthenticationCeremonyStorageImpl">A class implementing the <see cref="IAuthenticationCeremonyStorage{TContext}" /> interface.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddAuthenticationCeremonyStorage<TContext, TAuthenticationCeremonyStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TAuthenticationCeremonyStorageImpl : class, IAuthenticationCeremonyStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IAuthenticationCeremonyStorage<TContext>, TAuthenticationCeremonyStorageImpl>();
        return builder;
    }

    /// <summary>
    ///     Adds an implementation of storage to DI, used for searching in the metadata provided by the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a> during WebAuthn registration and authentication ceremonies.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <typeparam name="TFidoMetadataSearchStorageImpl">A class implementing the <see cref="IFidoMetadataSearchStorage{TContext}" /> interface.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddFidoMetadataSearchStorage<TContext, TFidoMetadataSearchStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TFidoMetadataSearchStorageImpl : class, IFidoMetadataSearchStorage<TContext>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IFidoMetadataSearchStorage<TContext>, TFidoMetadataSearchStorageImpl>();
        return builder;
    }

    /// <summary>
    ///     Adds an implementation of storage to DI, used for background ingest of metadata provided by the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <typeparam name="TFidoMetadataIngestStorageImpl">A class implementing the <see cref="IFidoMetadataIngestStorage" /> interface.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddFidoMetadataIngestStorage<TContext, TFidoMetadataIngestStorageImpl>(
        this IWebAuthnBuilder<TContext> builder)
        where TContext : class, IWebAuthnContext
        where TFidoMetadataIngestStorageImpl : class, IFidoMetadataIngestStorage
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IFidoMetadataIngestStorage, TFidoMetadataIngestStorageImpl>();
        return builder;
    }

    /// <summary>
    ///     Adds an implementation of storage to DI, used for storing and searching keys during WebAuthn registration and authentication ceremonies.
    /// </summary>
    /// <param name="builder">An extensible <see cref="IWebAuthnBuilder{TContext}" />  instance for configuring the collection of services responsible for handling WebAuthn operations.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <typeparam name="TCredentialStorageImpl">A class implementing the <see cref="ICredentialStorage{TContext}" /> interface.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
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
