using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.InMemory.Models;

namespace WebAuthn.Net.Storage.InMemory.Configuration.Builder;

/// <summary>
///     Builder for configuring the DI service collection, responsible for handling WebAuthn operations with in-memory storage.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed. Must be <see cref="DefaultInMemoryContext" /> or its descendant.</typeparam>
public interface IInMemoryWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultInMemoryContext
{
}
