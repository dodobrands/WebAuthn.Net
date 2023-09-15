using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Attestation;
using WebAuthn.Net.Services.Attestation.Models;

namespace WebAuthn.Net.Services.Attestation;

public interface IAttestationService
{
    Task<CredentialCreationOptions> CreateOptionsAsync(
        HttpContext httpContext,
        CredentialCreationOptionsRequest request,
        CancellationToken cancellationToken);

    Task<Result<HandleAttestationResponse>> HandleAsync(
        HttpContext httpContext,
        HandleAttestationRequest request,
        CancellationToken cancellationToken);
}
