namespace WebAuthn.Net.Demo.Mvc.Services.Abstractions.RegistrationCeremonyHandle;

public interface IRegistrationCeremonyHandleService
{
    Task SaveAsync(HttpContext httpContext, string registrationCeremonyId, CancellationToken cancellationToken);

    Task<string?> ReadAsync(HttpContext httpContext, CancellationToken cancellationToken);

    Task DeleteAsync(HttpContext httpContext, CancellationToken cancellationToken);
}
