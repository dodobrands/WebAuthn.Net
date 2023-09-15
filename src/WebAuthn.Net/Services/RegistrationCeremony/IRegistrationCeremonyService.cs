using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony;

public interface IRegistrationCeremonyService
{
    Task<BeginCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginCeremonyRequest request,
        CancellationToken cancellationToken);

    Task<Result<RegistrationCeremonyResult>> HandleAsync(
        HttpContext httpContext,
        RegistrationCeremonyRequest request,
        CancellationToken cancellationToken);
}
