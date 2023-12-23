namespace WebAuthn.Net.Demo.Mvc.Services.Abstractions.AuthenticationCeremonyHandle;

public interface IAuthenticationCeremonyHandleService
{
    Task SaveAsync(HttpContext httpContext, string authenticationCeremonyId, CancellationToken cancellationToken);

    Task<string?> ReadAsync(HttpContext httpContext, CancellationToken cancellationToken);

    Task DeleteAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
