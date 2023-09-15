using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony;

public interface IRegistrationCeremonyService
{
    Task<CredentialCreationOptions> CreateOptionsAsync(
        HttpContext httpContext,
        CredentialCreationOptionsRequest request,
        CancellationToken cancellationToken);

    Task<Result<RegistrationCeremonyResult>> HandleAsync(
        HttpContext httpContext,
        RegistrationCeremonyRequest request,
        CancellationToken cancellationToken);
}
