using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

namespace WebAuthn.Net.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
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
