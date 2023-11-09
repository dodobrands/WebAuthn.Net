using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.InMemory.Models;

namespace WebAuthn.Net.Storage.InMemory.Configuration.Builder;

public class InMemoryWebAuthnBuilder<TContext> : IInMemoryWebAuthnBuilder<TContext>
    where TContext : DefaultInMemoryContext
{
    public InMemoryWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
