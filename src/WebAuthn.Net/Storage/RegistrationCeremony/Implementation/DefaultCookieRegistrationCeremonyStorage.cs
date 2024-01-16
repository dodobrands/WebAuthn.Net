using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation.Models;
using WebAuthn.Net.Storage.RegistrationCeremony.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

/// <summary>
///     Default implementation of <see cref="IRegistrationCeremonyStorage{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultCookieRegistrationCeremonyStorage<TContext> : IRegistrationCeremonyStorage<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     The purpose of the Data Protector.
    /// </summary>
    public const string DataProtectionPurpose = "WebAuthn.Net.DefaultCookieRegistrationCeremonyStorage";

    /// <summary>
    ///     Constructs <see cref="DefaultCookieRegistrationCeremonyStorage{TContext}" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of the default registration ceremony storage options.</param>
    /// <param name="provider">Provider for creating <see cref="IDataProtector" />.</param>
    /// <param name="safeJsonSerializer">Safe (exceptionless) JSON serializer.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultCookieRegistrationCeremonyStorage(
        IOptionsMonitor<DefaultCookieRegistrationCeremonyStorageOptions> options,
        IDataProtectionProvider provider,
        ISafeJsonSerializer safeJsonSerializer)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(provider);
        ArgumentNullException.ThrowIfNull(safeJsonSerializer);
        Options = options;
        Protector = provider.CreateProtector(DataProtectionPurpose, "v1");
        CookieManager = new ChunkingCookieManager();
        SafeJsonSerializer = safeJsonSerializer;
    }

    /// <summary>
    ///     Accessor for getting the current value of the default registration ceremony storage options.
    /// </summary>
    protected IOptionsMonitor<DefaultCookieRegistrationCeremonyStorageOptions> Options { get; }

    /// <summary>
    ///     Protector for encrypting and decrypting sensitive data.
    /// </summary>
    protected IDataProtector Protector { get; }

    /// <summary>
    ///     Manager for working with Cookies, abstracting away from direct interaction with the Cookie API.
    /// </summary>
    protected ICookieManager CookieManager { get; }

    /// <summary>
    ///     Safe (exceptionless) JSON serializer.
    /// </summary>
    protected ISafeJsonSerializer SafeJsonSerializer { get; }

    /// <inheritdoc />
    public virtual Task<string> SaveAsync(
        TContext context,
        RegistrationCeremonyParameters registrationCeremonyParameters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var options = Options.CurrentValue;
        var id = Guid.NewGuid().ToString("N").ToLowerInvariant();
        var container = new RegistrationCeremonyParametersCookieContainer(id, registrationCeremonyParameters);
        var jsonBytesResult = SafeJsonSerializer.SerializeToUtf8Bytes(container, options.SerializerOptions);
        if (jsonBytesResult.HasError)
        {
            throw new InvalidOperationException($"Failed to serialize {nameof(RegistrationCeremonyParametersCookieContainer)} into json");
        }

        var jsonBytes = jsonBytesResult.Ok;
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

    /// <inheritdoc />
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

            if (!Base64Url.TryDecode(encodedProtectedJsonBytes, out var protectedJsonBytes))
            {
                return Task.FromResult((RegistrationCeremonyParameters?) null);
            }

            var jsonBytes = Protector.Unprotect(protectedJsonBytes);
            var containerResult = SafeJsonSerializer.DeserializeNonNullable<RegistrationCeremonyParametersCookieContainer>(jsonBytes, options.SerializerOptions);
            if (containerResult.HasError)
            {
                return Task.FromResult((RegistrationCeremonyParameters?) null);
            }

            var container = containerResult.Ok;
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

    /// <inheritdoc />
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

            if (!Base64Url.TryDecode(encodedProtectedJsonBytes, out var protectedJsonBytes))
            {
                return Task.FromResult((RegistrationCeremonyParameters?) null);
            }

            var jsonBytes = Protector.Unprotect(protectedJsonBytes);
            var containerResult = SafeJsonSerializer.DeserializeNonNullable<RegistrationCeremonyParametersCookieContainer>(jsonBytes, options.SerializerOptions);
            if (containerResult.HasError)
            {
                return Task.CompletedTask;
            }

            var container = containerResult.Ok;
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

    /// <summary>
    ///     Returns the name of the cookie that is used to store the registration ceremony data.
    /// </summary>
    /// <param name="options">Options for the default registration ceremony store that operates on cookies.</param>
    /// <returns>The name of the cookie used for storing the registration ceremony data.</returns>
    protected virtual string GetCookieName(DefaultCookieRegistrationCeremonyStorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        return options.Cookie.Name ?? DefaultCookieRegistrationCeremonyStorageOptions.CookieName;
    }
}
