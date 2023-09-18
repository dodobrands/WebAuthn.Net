using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IWebAuthnBuilder<TContext> AddWebAuthn<TContext>(
        this IServiceCollection services,
        Action<WebAuthnOptions>? configure = null)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(services);
        return new WebAuthnBuilder<TContext>(services).AddCoreServices(configure);
    }
}
