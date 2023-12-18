using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Configuration.Builder;

/// <summary>
///     Default implementation of <see cref="IMySqlWebAuthnBuilder{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultMySqlContext" /> or its descendant.</typeparam>
public class MySqlWebAuthnBuilder<TContext> : IMySqlWebAuthnBuilder<TContext>
    where TContext : DefaultMySqlContext
{
    /// <summary>
    ///     Constructs <see cref="MySqlWebAuthnBuilder{TContext}" />.
    /// </summary>
    /// <param name="services">A collection of services to which services will be added (using the extension methods for this builder) responsible for handling WebAuthn operations with a MySQL-based storage.</param>
    /// <exception cref="ArgumentNullException"><paramref name="services" /> is <see langword="null" /></exception>
    public MySqlWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
