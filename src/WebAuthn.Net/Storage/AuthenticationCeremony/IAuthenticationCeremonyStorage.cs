using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Storage.AuthenticationCeremony;

/// <summary>
///     Storage for authentication ceremony data.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface IAuthenticationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Saves the parameters of the specified authentication ceremony and returns the unique identifier of the saved record.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="authenticationCeremony">Authentication ceremony parameters.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>Unique identifier of the saved authentication ceremony parameters.</returns>
    Task<string> SaveAsync(
        TContext context,
        AuthenticationCeremonyParameters authenticationCeremony,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Finds the parameters of the authentication ceremony by the specified id.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="authenticationCeremonyId">Unique identifier of previously saved authentication ceremony parameters.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An instance of <see cref="AuthenticationCeremonyParameters" /> if authentication ceremony parameters were found for the specified identifier, otherwise - <see langword="null" />.</returns>
    Task<AuthenticationCeremonyParameters?> FindAsync(
        TContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Deletes authentication ceremony parameters with the specified identifier.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="authenticationCeremonyId">Unique identifier of previously saved authentication ceremony parameters.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task RemoveAsync(
        TContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken);
}
