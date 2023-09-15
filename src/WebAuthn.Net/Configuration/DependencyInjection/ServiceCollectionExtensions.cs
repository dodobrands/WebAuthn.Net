using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IWebAuthnNetBuilder<TContext> AddWebAuthnNet<TContext>(this IServiceCollection services)
        where TContext : class, IWebAuthnContext
    {
        ArgumentNullException.ThrowIfNull(services);
        return new WebAuthnNetBuilder<TContext>(services)
            .AddCoreServices();
    }
}
