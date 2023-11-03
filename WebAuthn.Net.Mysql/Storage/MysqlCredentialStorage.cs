using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Mysql.Storage;

public sealed class MysqlCredentialStorage : MysqlCredentialStorage<IWebAuthnContext>
{
}

public class MysqlCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    public async Task<PublicKeyCredentialDescriptor[]?> FindDescriptorsAsync(TContext context, string rpId, byte[] userHandle, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<UserCredentialRecord?> FindCredentialAsync(TContext context, string rpId, byte[] userHandle, byte[] credentialId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<bool> SaveIfNotRegisteredForOtherUserAsync(TContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task<bool> UpdateCredentialAsync(TContext context, UserCredentialRecord credential, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
