using WebAuthn.Net.Configuration.Builder;
using WebAuthn.Net.Storage.InMemory.Models;

namespace WebAuthn.Net.Storage.InMemory.Configuration.Builder;

public interface IInMemoryWebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : DefaultInMemoryContext
{
}
