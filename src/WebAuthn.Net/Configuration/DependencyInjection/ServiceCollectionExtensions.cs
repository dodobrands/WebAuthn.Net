using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

namespace WebAuthn.Net.Configuration.DependencyInjection;

/// <summary>
///     Extension methods to <see cref="IServiceCollection" /> for configuring up WebAuthn.Net.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    ///     Adds the essential services to <see cref="IServiceCollection" />, which are necessary for WebAuthn.Net
    /// </summary>
    /// <param name="services">Service collection.</param>
    /// <param name="configure">An optional delegate for configuring global WebAuthn.Net options.</param>
    /// <param name="configureFidoHttpClientBuilder">
    ///     An optional delegate for configuring the HttpClient that will be used to access the <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>. Here you can add retries using
    ///     <a href="https://github.com/App-vNext/Polly">Polly</a>, set timeouts, add your own DelegatingHandlers, or otherwise customize the behavior of HttpClient.
    /// </param>
    /// <param name="configureBackgroundIngest">An optional delegate for configuring the behavior of metadata ingestion from <a href="https://fidoalliance.org/metadata">FIDO Metadata Service</a>.</param>
    /// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
    /// <returns>An instance of <see cref="IWebAuthnBuilder{TContext}" /> that can be used to call additional WebAuthn.Net extension methods.</returns>
    public static IWebAuthnBuilder<TContext> AddWebAuthnCore<TContext>(
        this IServiceCollection services,
        Action<WebAuthnOptions>? configure = null,
        Action<IHttpClientBuilder>? configureFidoHttpClientBuilder = null,
        Action<FidoMetadataBackgroundIngestHostedServiceOptions>? configureBackgroundIngest = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(services);
        return new WebAuthnBuilder<TContext>(services)
            .AddCoreServices(configure, configureFidoHttpClientBuilder, configureBackgroundIngest);
    }
}
