using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Storage.CredentialStorage;

public class DefaultMySqlCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : DefaultMySqlContext
{
    public Task<PublicKeyCredentialDescriptor[]?> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<UserCredentialRecord?> FindCredentialAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}
