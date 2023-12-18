using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.SqlServer.Models;

namespace WebAuthn.Net.Storage.SqlServer.Configuration.Builder;

/// <summary>
///     Default implementation of <see cref="ISqlServerWebAuthnBuilder{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultSqlServerContext" /> or its descendant.</typeparam>
public class SqlServerWebAuthnBuilder<TContext> : ISqlServerWebAuthnBuilder<TContext>
    where TContext : DefaultSqlServerContext
{
    /// <summary>
    ///     Constructs <see cref="SqlServerWebAuthnBuilder{TContext}" />.
    /// </summary>
    /// <param name="services">A collection of services to which services will be added (using the extension methods for this builder) responsible for handling WebAuthn operations with a Microsoft SQL Server-based storage.</param>
    /// <exception cref="ArgumentNullException"><paramref name="services" /> is <see langword="null" /></exception>
    public SqlServerWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    /// <inheritdoc />
    public IServiceCollection Services { get; }
}
