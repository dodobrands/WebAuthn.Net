using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateCredential;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

namespace WebAuthn.Net.Services.RegistrationCeremony;

public interface IRegistrationCeremonyService
{
    Task<BeginRegistrationCeremonyResult> BeginCeremonyAsync(
        HttpContext httpContext,
        BeginRegistrationCeremonyRequest request,
        CancellationToken cancellationToken);

    Task<Result<CompleteRegistrationCeremonyResult>> CompleteCeremonyAsync(
        HttpContext httpContext,
        CompleteRegistrationCeremonyRequest request,
        CancellationToken cancellationToken);
}
