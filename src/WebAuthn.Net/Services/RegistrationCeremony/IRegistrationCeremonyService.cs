using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony;

/// <summary>
///     The service responsible for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#registration-ceremony">creating a public key credential and associating it with a user account</a>.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-registering-a-new-credential">Web Authentication: An API for accessing Public Key Credentials Level 3 - §7.1. Registering a New Credential</a>
/// </remarks>
public interface IRegistrationCeremonyService
{
    /// <summary>
    ///     Asynchronously initiates the registration ceremony, generating parameters for its execution.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="request">Request containing parameters for generating the registration ceremony options.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The result of initiating the registration ceremony.</returns>
    Task<BeginRegistrationCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginRegistrationCeremonyRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Asynchronously completes the registration ceremony.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="request">Request containing parameters for completing the registration ceremony.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The result of completing the registration ceremony.</returns>
    Task<Result<CompleteRegistrationCeremonyResult>> CompleteCeremonyAsync(
        HttpContext httpContext,
        CompleteRegistrationCeremonyRequest request,
        CancellationToken cancellationToken);
}
