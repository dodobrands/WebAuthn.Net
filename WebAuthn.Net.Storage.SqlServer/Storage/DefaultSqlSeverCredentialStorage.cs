using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.SqlServer.Models;

namespace WebAuthn.Net.Storage.SqlServer.Storage;

public class DefaultSqlSeverCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : DefaultSqlServerContext
{
    public async Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(TContext context, string rpId, byte[] userHandle, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(TContext context, string rpId, byte[] userHandle, byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task<bool> SaveIfNotRegisteredForOtherUserAsync(TContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task<bool> UpdateCredentialAsync(TContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(credential);
        await Task.Yield();
        throw new NotImplementedException();
    }
}
