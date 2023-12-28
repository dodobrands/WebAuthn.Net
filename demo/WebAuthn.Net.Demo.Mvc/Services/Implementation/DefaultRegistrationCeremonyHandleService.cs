using System.Text;
using Microsoft.AspNetCore.DataProtection;
using WebAuthn.Net.Demo.Mvc.Constants;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.CookieStore;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.RegistrationCeremonyHandle;

namespace WebAuthn.Net.Demo.Mvc.Services.Implementation;

public class DefaultRegistrationCeremonyHandleService(IDataProtectionProvider provider)
    : AbstractProtectedCookieStore(provider, DataProtectionPurpose, CookieConstants.RegistrationCeremonyId), IRegistrationCeremonyHandleService
{
    private const string DataProtectionPurpose = "WebAuthn.Net.Demo.RegistrationCeremonyHandle";

    public Task SaveAsync(HttpContext httpContext, string registrationCeremonyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Save(httpContext, Encoding.UTF8.GetBytes(registrationCeremonyId));
        return Task.CompletedTask;
    }

    public Task<string?> ReadAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (TryRead(httpContext, out var registrationCeremonyId))
        {
            return Task.FromResult<string?>(Encoding.UTF8.GetString(registrationCeremonyId));
        }

        return Task.FromResult<string?>(null);
    }

    public Task DeleteAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Delete(httpContext);
        return Task.CompletedTask;
    }
}
