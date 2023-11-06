using System;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;

public class DefaultCookieAuthenticationCeremonyStorageOptions
{
    public const string CookieName = "webauthn.a";

    private CookieBuilder _cookieBuilder = new RequestPathBaseCookieBuilder
    {
        Name = CookieName,
        SameSite = SameSiteMode.Lax,
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

    public JsonSerializerOptions SerializerOptions
    {
        get => _serializerOptions;
        set => _serializerOptions = value ?? throw new ArgumentNullException(nameof(value));
    }

    public CookieBuilder Cookie
    {
        get => _cookieBuilder;
        set => _cookieBuilder = value ?? throw new ArgumentNullException(nameof(value));
    }
}
