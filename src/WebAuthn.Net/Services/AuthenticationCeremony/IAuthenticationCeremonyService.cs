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
    Task<BeginAuthenticationCeremonyResult> CreateOptionsAsync(
        HttpContext httpContext,
        BeginAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken);

    Task<CompleteAuthenticationCeremonyResult> HandleAsync(
        HttpContext httpContext,
        CompleteAuthenticationCeremonyRequest request,
        CancellationToken cancellationToken);
}
