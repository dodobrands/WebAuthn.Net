using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Assertion;
using WebAuthn.Net.Services.Assertion.Models;

namespace WebAuthn.Net.Services.Assertion;

public interface IAssertionService
{
    Task<CredentialRequestOptions> CreateOptionsAsync(
        HttpContext httpContext,
        CredentialRequestOptionsRequest request,
        CancellationToken cancellationToken);

    Task<Result<HandleAssertionResponse>> HandleAsync(
        HttpContext httpContext,
        HandleAssertionRequest request,
        CancellationToken cancellationToken);
}
