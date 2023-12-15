using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.Configuration.Builder;

/// <summary>
///     Builder for configuring the DI service collection, responsible for processing WebAuthn operations.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface IWebAuthnBuilder<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     A collection of services to which, using extension methods for this builder, will be added services responsible for handling WebAuthn operations.
    /// </summary>
    IServiceCollection Services { get; }
}
