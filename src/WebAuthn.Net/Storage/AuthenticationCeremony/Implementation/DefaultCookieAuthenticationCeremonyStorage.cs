using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation.Models;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;

public class DefaultCookieAuthenticationCeremonyStorage<TContext> : IAuthenticationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    private const string DataProtectionPurpose = "WebAuthn.Net.DefaultCookieAuthenticationCeremonyStorage";

    public DefaultCookieAuthenticationCeremonyStorage(
        IOptionsMonitor<DefaultCookieAuthenticationCeremonyStorageOptions> options,
        IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(provider);
        Options = options;
        Protector = provider.CreateProtector(DataProtectionPurpose, "v1");
        CookieManager = new ChunkingCookieManager();
    }

    protected IOptionsMonitor<DefaultCookieAuthenticationCeremonyStorageOptions> Options { get; }
    protected IDataProtector Protector { get; }
    protected ICookieManager CookieManager { get; }

    public virtual Task<string> SaveAsync(
        TContext context,
        AuthenticationCeremonyParameters authenticationCeremony,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var id = Guid.NewGuid().ToString("N").ToLowerInvariant();
        var container = new AuthenticationCeremonyParametersCookieContainer(id, authenticationCeremony);
        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(container, options.SerializerOptions);
        var protectedJsonBytes = Protector.Protect(jsonBytes);
        var encodedProtectedJsonBytes = Base64Url.Encode(protectedJsonBytes);
        var cookieOptions = options.Cookie.Build(context.HttpContext);
        var cookieName = GetCookieName(options);
        CookieManager.AppendResponseCookie(
            context.HttpContext,
            cookieName,
            encodedProtectedJsonBytes,
            cookieOptions);
        return Task.FromResult(id);
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public Task<AuthenticationCeremonyParameters?> FindAsync(
        TContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var cookieName = GetCookieName(options);
        try
        {
            var id = new Guid(authenticationCeremonyId).ToString("N").ToLowerInvariant();
            var encodedProtectedJsonBytes = CookieManager.GetRequestCookie(context.HttpContext, cookieName);
            if (encodedProtectedJsonBytes is null)
            {
                return Task.FromResult((AuthenticationCeremonyParameters?) null);
            }

            if (!Base64Url.TryDecode(encodedProtectedJsonBytes, out var protectedJsonBytes))
            {
                return Task.FromResult((AuthenticationCeremonyParameters?) null);
            }

            var jsonBytes = Protector.Unprotect(protectedJsonBytes);
            var container = JsonSerializer.Deserialize<AuthenticationCeremonyParametersCookieContainer>(jsonBytes, options.SerializerOptions);
            if (container is not null && container.Id == id)
            {
                return Task.FromResult<AuthenticationCeremonyParameters?>(container.AuthenticationCeremonyParameters);
            }

            return Task.FromResult((AuthenticationCeremonyParameters?) null);
        }
        catch (Exception)
        {
            return Task.FromResult((AuthenticationCeremonyParameters?) null);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public Task RemoveAsync(
        TContext context,
        string authenticationCeremonyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var cookieOptions = options.Cookie.Build(context.HttpContext);
        var cookieName = GetCookieName(options);
        try
        {
            var id = new Guid(authenticationCeremonyId).ToString("N").ToLowerInvariant();
            var encodedProtectedJsonBytes = CookieManager.GetRequestCookie(context.HttpContext, cookieName);
            if (encodedProtectedJsonBytes is null)
            {
                return Task.CompletedTask;
            }

            if (!Base64Url.TryDecode(encodedProtectedJsonBytes, out var protectedJsonBytes))
            {
                return Task.FromResult((AuthenticationCeremonyParameters?) null);
            }

            var jsonBytes = Protector.Unprotect(protectedJsonBytes);
            var container = JsonSerializer.Deserialize<AuthenticationCeremonyParametersCookieContainer>(jsonBytes, options.SerializerOptions);
            if (container is not null && container.Id == id)
            {
                CookieManager.DeleteCookie(context.HttpContext, cookieName, cookieOptions);
            }

            return Task.CompletedTask;
        }
        catch (Exception)
        {
            return Task.CompletedTask;
        }
    }

    protected virtual string GetCookieName(DefaultCookieAuthenticationCeremonyStorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.Cookie.Name ?? DefaultCookieAuthenticationCeremonyStorageOptions.CookieName;
    }
}
