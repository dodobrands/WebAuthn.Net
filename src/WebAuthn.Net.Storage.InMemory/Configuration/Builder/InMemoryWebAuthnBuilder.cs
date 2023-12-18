using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.InMemory.Models;

namespace WebAuthn.Net.Storage.InMemory.Configuration.Builder;

/// <summary>
///     Default implementation of <see cref="IInMemoryWebAuthnBuilder{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultInMemoryContext" /> or its descendant.</typeparam>
public class InMemoryWebAuthnBuilder<TContext> : IInMemoryWebAuthnBuilder<TContext>
    where TContext : DefaultInMemoryContext
{
    /// <summary>
    ///     Constructs <see cref="InMemoryWebAuthnBuilder{TContext}" />.
    /// </summary>
    /// <param name="services">A collection of services to which services will be added (using the extension methods for this builder), responsible for handling WebAuthn operations with an in-memory storage.</param>
    /// <exception cref="ArgumentNullException"><paramref name="services" /> is <see langword="null" /></exception>
    public InMemoryWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
