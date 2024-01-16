using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony;

/// <summary>
///     Storage for registration ceremony data.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface IRegistrationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Saves the parameters of the specified registration ceremony and returns the unique identifier of the saved record.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="registrationCeremonyParameters">Registration ceremony parameters.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns></returns>
    Task<string> SaveAsync(
        TContext context,
        RegistrationCeremonyParameters registrationCeremonyParameters,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Finds the registration ceremony parameters by the specified id.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="registrationCeremonyId">Unique identifier of the previously saved registration ceremony parameters.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>An instance of <see cref="RegistrationCeremonyParameters" /> if the registration ceremony parameters were found for the specified identifier, otherwise - <see langword="null" />.</returns>
    Task<RegistrationCeremonyParameters?> FindAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Deletes the registration ceremony parameters with the specified identifier.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="registrationCeremonyId">Unique identifier of the previously saved registration ceremony parameters.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    Task RemoveAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken);
}
