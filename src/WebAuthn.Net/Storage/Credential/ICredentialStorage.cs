using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Storage.Credential;

public interface ICredentialStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken);

    Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken);

    Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken);

    Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken);
}
