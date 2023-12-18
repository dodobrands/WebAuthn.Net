using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.PostgreSql.Models;

namespace WebAuthn.Net.Storage.PostgreSql.Configuration.Builder;

/// <summary>
///     Default implementation of <see cref="IPostgreSqlWebAuthnBuilder{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultPostgreSqlContext" /> or its descendant.</typeparam>
public class PostgreSqlWebAuthnBuilder<TContext> : IPostgreSqlWebAuthnBuilder<TContext>
    where TContext : DefaultPostgreSqlContext
{
    /// <summary>
    ///     Constructs <see cref="PostgreSqlWebAuthnBuilder{TContext}" />.
    /// </summary>
    /// <param name="services">A collection of services to which services will be added (using the extension methods for this builder) responsible for handling WebAuthn operations with a PostgreSQL-based storage.</param>
    /// <exception cref="ArgumentNullException"><paramref name="services" /> is <see langword="null" /></exception>
    public PostgreSqlWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
