using System.Text;
using Microsoft.AspNetCore.DataProtection;
using WebAuthn.Net.Demo.Mvc.Constants;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.AuthenticationCeremonyHandle;
using WebAuthn.Net.Demo.Mvc.Services.Abstractions.CookieStore;

namespace WebAuthn.Net.Demo.Mvc.Services.Implementation;

public class DefaultAuthenticationCeremonyHandleService(IDataProtectionProvider provider)
    : AbstractProtectedCookieStore(provider, DataProtectionPurpose, CookieConstants.AuthenticationCeremonyId), IAuthenticationCeremonyHandleService
{
    private const string DataProtectionPurpose = "WebAuthn.Net.Demo.AuthenticationCeremonyHandle";

    public Task SaveAsync(HttpContext httpContext, string authenticationCeremonyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Save(httpContext, Encoding.UTF8.GetBytes(authenticationCeremonyId));
        return Task.CompletedTask;
    }

    public Task<string?> ReadAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (TryRead(httpContext, out var authenticationCeremonyId))
        {
            return Task.FromResult<string?>(Encoding.UTF8.GetString(authenticationCeremonyId));
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
