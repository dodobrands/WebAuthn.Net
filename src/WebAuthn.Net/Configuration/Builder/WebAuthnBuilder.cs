using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Configuration.Builder;

/// <summary>
///     Default implementation of <see cref="IWebAuthnBuilder{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class WebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="WebAuthnBuilder{TContext}" />.
    /// </summary>
    /// <param name="services">A collection of services to which, using extension methods for this builder, will be added services responsible for handling WebAuthn operations.</param>
    /// <exception cref="ArgumentNullException"><paramref name="services" /> is <see langword="null" /></exception>
    public WebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
