using System;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

/// <summary>
///     Options for the default registration ceremony store that operates on cookies.
/// </summary>
public class DefaultCookieRegistrationCeremonyStorageOptions
{
    /// <summary>
    ///     The name of the cookie that will be used by default
    /// </summary>
    public const string CookieName = "webauthnr";

    private CookieBuilder _cookieBuilder = new RequestPathBaseCookieBuilder
    {
        Name = CookieName,
        SameSite = SameSiteMode.None,
        HttpOnly = true,
        SecurePolicy = CookieSecurePolicy.Always,
        IsEssential = true
    };

    private JsonSerializerOptions _serializerOptions = new(JsonSerializerDefaults.General)
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        WriteIndented = false
    };

    /// <summary>
    ///     Serializer settings.
    /// </summary>
    /// <exception cref="ArgumentNullException">If the value is <see langword="null" />.</exception>
    public JsonSerializerOptions SerializerOptions
    {
        get => _serializerOptions;
        set => _serializerOptions = value ?? throw new ArgumentNullException(nameof(value));
    }

    /// <summary>
    ///     Cookie settings.
    /// </summary>
    /// <exception cref="ArgumentNullException">If the value is <see langword="null" />.</exception>
    public CookieBuilder Cookie
    {
        get => _cookieBuilder;
        set => _cookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
    }
}
