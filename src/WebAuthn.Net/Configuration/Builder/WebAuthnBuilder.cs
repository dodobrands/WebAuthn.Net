using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Configuration.Builder;

public class WebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : class, IWebAuthnContext
{
    public WebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
