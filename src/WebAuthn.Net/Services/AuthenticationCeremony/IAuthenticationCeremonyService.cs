using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;
using WebAuthn.Net.Services.AuthenticationCeremony.Models.VerifyAssertion;

namespace WebAuthn.Net.Services.AuthenticationCeremony;

/// <summary>
///     The service responsible for verifying and processing an <a href="https://www.w3.org/TR/webauthn-3/#authentication-assertion">authentication assertion</a>
///     to perform the <a href="https://www.w3.org/TR/webauthn-3/#authentication-ceremony">authentication ceremony</a>.
/// </summary>
/// <remarks>
///     <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">Web Authentication: An API for accessing Public Key Credentials Level 3 - §7.2. Verifying an Authentication Assertion</a>
/// </remarks>
public interface IAuthenticationCeremonyService
{
    /// <summary>
    ///     Asynchronously initiates the authentication ceremony, generating options in order to execute it.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="request">A request containing the parameters for generating options for the authentication ceremony.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The result of initiating the authentication ceremony.</returns>
    Task<BeginAuthenticationCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken);

    /// <summary>
    ///     Asynchronously completes the authentication ceremony.
    /// </summary>
    /// <param name="httpContext">The context of the HTTP request in which the WebAuthn operation is being processed.</param>
    /// <param name="request">A request containing the parameters for completing the authentication ceremony.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>The result of completing the authentication ceremony.</returns>
    Task<CompleteAuthenticationCeremonyResult> CompleteCeremonyAsync(
        HttpContext httpContext,
        CompleteAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken);
}
