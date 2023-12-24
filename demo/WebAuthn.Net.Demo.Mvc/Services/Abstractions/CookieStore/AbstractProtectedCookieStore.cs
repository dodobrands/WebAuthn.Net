using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Demo.Mvc.Services.Abstractions.CookieStore;

public abstract class AbstractProtectedCookieStore
{
    private readonly CookieBuilder _cookieBuilder;
    private readonly ChunkingCookieManager _cookieManager;
    private readonly string _cookieName;
    private readonly IDataProtector _protector;

    protected AbstractProtectedCookieStore(
        IDataProtectionProvider provider,
        string dataProtectionPurpose,
        string cookieName)
    {
        ArgumentNullException.ThrowIfNull(provider);
        if (string.IsNullOrEmpty(dataProtectionPurpose))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(dataProtectionPurpose));
        }

        if (string.IsNullOrEmpty(cookieName))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(cookieName));
        }

        _protector = provider.CreateProtector(dataProtectionPurpose);
        _cookieManager = new();
        _cookieBuilder = new RequestPathBaseCookieBuilder
        {
            Name = cookieName,
            SameSite = SameSiteMode.None,
            HttpOnly = true,
            SecurePolicy = CookieSecurePolicy.Always,
            IsEssential = true
        };
        _cookieName = cookieName;
    }

    protected void Save(HttpContext httpContext, byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var protectedBytes = _protector.Protect(payload);
        var encodedProtectedBytes = Base64Url.Encode(protectedBytes);
        var cookieOptions = _cookieBuilder.Build(httpContext);
        _cookieManager.AppendResponseCookie(
            httpContext,
            _cookieName,
            encodedProtectedBytes,
            cookieOptions);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    protected bool TryRead(HttpContext httpContext, [NotNullWhen(true)] out byte[]? payload)
    {
        try
        {
            var encodedProtectedBytes = _cookieManager.GetRequestCookie(httpContext, _cookieName);
            if (encodedProtectedBytes is null)
            {
                payload = null;
                return false;
            }

            if (!Base64Url.TryDecode(encodedProtectedBytes, out var protectedBytes))
            {
                payload = null;
                return false;
            }

            payload = _protector.Unprotect(protectedBytes);
            return true;
        }
        catch
        {
            payload = null;
            return false;
        }
    }

    protected void Delete(HttpContext httpContext)
    {
        var cookieOptions = _cookieBuilder.Build(httpContext);
        _cookieManager.DeleteCookie(httpContext, _cookieName, cookieOptions);
    }
}
