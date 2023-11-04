using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Mysql.Models;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Mysql.Storage;

public class MysqlCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : MySqlWebAuthnContext
{
    public async Task<PublicKeyCredentialDescriptor[]?> FindDescriptorsAsync(TContext context, string rpId, byte[] userHandle, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task<UserCredentialRecord?> FindCredentialAsync(TContext context, string rpId, byte[] userHandle, byte[] credentialId, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task<bool> SaveIfNotRegisteredForOtherUserAsync(TContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }

    public async Task<bool> UpdateCredentialAsync(TContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        await Task.Yield();
        throw new NotImplementedException();
    }
}
