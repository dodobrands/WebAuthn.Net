using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation.Models;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

public class DefaultCookieRegistrationCeremonyStorage<TContext> : IRegistrationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    private const string DataProtectionPurpose = "WebAuthn.Net.DefaultCookieRegistrationCeremonyStorage";

    public DefaultCookieRegistrationCeremonyStorage(
        IOptionsMonitor<DefaultCookieRegistrationCeremonyStorageOptions> options,
        IDataProtectionProvider provider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(provider);
        Options = options;
        Protector = provider.CreateProtector(DataProtectionPurpose, "v1");
        CookieManager = new ChunkingCookieManager();
    }

    protected IOptionsMonitor<DefaultCookieRegistrationCeremonyStorageOptions> Options { get; }
    protected IDataProtector Protector { get; }
    protected ICookieManager CookieManager { get; }

    public virtual Task<string> SaveAsync(
        TContext context,
        RegistrationCeremonyParameters registrationCeremony,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var id = Guid.NewGuid().ToString("N").ToLowerInvariant();
        var container = new RegistrationCeremonyParametersCookieContainer(id, registrationCeremony);
        var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(container, options.SerializerOptions);
        var protectedJsonBytes = Protector.Protect(jsonBytes);
        var encodedProtectedJsonBytes = WebEncoders.Base64UrlEncode(protectedJsonBytes);
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
    public virtual Task<RegistrationCeremonyParameters?> FindAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var cookieName = GetCookieName(options);
        try
        {
            var id = new Guid(registrationCeremonyId).ToString("N").ToLowerInvariant();
            var encodedProtectedJsonBytes = CookieManager.GetRequestCookie(context.HttpContext, cookieName);
            if (encodedProtectedJsonBytes is null)
            {
                return Task.FromResult((RegistrationCeremonyParameters?) null);
            }

            var protectedJsonBytes = WebEncoders.Base64UrlDecode(encodedProtectedJsonBytes);
            var jsonBytes = Protector.Unprotect(protectedJsonBytes);
            var container = JsonSerializer.Deserialize<RegistrationCeremonyParametersCookieContainer>(jsonBytes, options.SerializerOptions);
            if (container is not null && container.Id == id)
            {
                return Task.FromResult<RegistrationCeremonyParameters?>(container.RegistrationCeremonyParameters);
            }

            return Task.FromResult((RegistrationCeremonyParameters?) null);
        }
        catch (Exception)
        {
            return Task.FromResult((RegistrationCeremonyParameters?) null);
        }
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    public virtual Task RemoveAsync(
        TContext context,
        string registrationCeremonyId,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var cookieOptions = options.Cookie.Build(context.HttpContext);
        var cookieName = GetCookieName(options);
        try
        {
            var id = new Guid(registrationCeremonyId).ToString("N").ToLowerInvariant();
            var encodedProtectedJsonBytes = CookieManager.GetRequestCookie(context.HttpContext, cookieName);
            if (encodedProtectedJsonBytes is null)
            {
                return Task.CompletedTask;
            }

            var protectedJsonBytes = WebEncoders.Base64UrlDecode(encodedProtectedJsonBytes);
            var jsonBytes = Protector.Unprotect(protectedJsonBytes);
            var container = JsonSerializer.Deserialize<RegistrationCeremonyParametersCookieContainer>(jsonBytes, options.SerializerOptions);
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

    protected virtual string GetCookieName(DefaultCookieRegistrationCeremonyStorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.Cookie.Name ?? DefaultCookieRegistrationCeremonyStorageOptions.CookieName;
    }
}
