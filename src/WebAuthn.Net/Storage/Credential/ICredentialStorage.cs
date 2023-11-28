using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Storage.Credential;

/// <summary>
///     Credential storage. This is where the credentials are located, providing methods for storing credentials that are created during the registration ceremony, as well as methods for accessing them during the authentication ceremony.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface ICredentialStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Finds credential descriptors for the specified user and rpId.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="rpId">rpId for which descriptors need to be found</param>
    /// <param name="userHandle">Unique user identifier.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Credential descriptors for the specified user and rpId. May be an empty array, but not <see langword="null" />.</returns>
    Task<PublicKeyCredentialDescriptor[]> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Returns information about the credential that will be used in the process of the authentication ceremony. It might internally perform a row lock for this record if the context mechanism is used to ensure the completion of the entire ceremony in a single transaction.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="rpId">rpId for which a credential needs to be found.</param>
    /// <param name="userHandle">Unique user identifier.</param>
    /// <param name="credentialId">Unique identifier of the credential (within <paramref name="rpId" /> and <paramref name="userHandle" />).</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Instance of <see cref="UserCredentialRecord" /> if such a credential with that <paramref name="credentialId" /> exists for the specified <paramref name="rpId" /> and <paramref name="userHandle" />. Otherwise - <see langword="null" />.</returns>
    Task<UserCredentialRecord?> FindExistingCredentialForAuthenticationAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Saves the specified credential if it has not previously been registered for another <see cref="UserCredentialRecord">credential</see>.<see cref="UserCredentialRecord.UserHandle">UserHandle</see> under the same <see cref="UserCredentialRecord">credential</see>.
    ///     <see cref="UserCredentialRecord.RpId">RpId</see> value and returns the status of the operation - whether it was successful in saving or not.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="credential">User credential that needs to be saved..</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If a credential with such a <see cref="UserCredentialRecord">credential</see>.<see cref="UserCredentialRecord.CredentialRecord">CredentialRecord</see>.<see cref="CredentialRecord.Id" /> was not previously registered for another
    ///     <see cref="UserCredentialRecord">credential</see>.<see cref="UserCredentialRecord.UserHandle">UserHandle</see> within <see cref="UserCredentialRecord">credential</see>.<see cref="UserCredentialRecord.RpId">RpId</see> and the save operation was successful - returns
    ///     <see langword="true" />. Otherwise, it returns <see langword="false" />.
    /// </returns>
    Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Updates the credential and returns the status of the operation - whether it was successful in updating or not.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="credential">User credential that needs to be updated.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>
    ///     If there exists a credential for the combination of <see cref="UserCredentialRecord">credential</see>.<see cref="UserCredentialRecord.CredentialRecord">CredentialRecord</see>.<see cref="CredentialRecord.Id" />, <see cref="UserCredentialRecord">credential</see>.
    ///     <see cref="UserCredentialRecord.UserHandle">UserHandle</see>, and <see cref="UserCredentialRecord">credential</see>.<see cref="UserCredentialRecord.RpId">RpId</see> values, then it updates it and returns the status of the update operation. If such a record exists and it was
    ///     successfully updated - returns <see langword="true" />. Otherwise, it returns <see langword="false" />.
    /// </returns>
    Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken);
}
