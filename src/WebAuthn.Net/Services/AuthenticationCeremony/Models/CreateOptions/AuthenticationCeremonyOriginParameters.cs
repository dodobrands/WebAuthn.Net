using System;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

public class AuthenticationCeremonyOriginParameters
{
    public AuthenticationCeremonyOriginParameters(string[] allowedOrigins)
    {
        ArgumentNullException.ThrowIfNull(allowedOrigins);
        if (allowedOrigins.Length == 0)
        {
            throw new ArgumentException($"The {nameof(allowedOrigins)} must contain at least one element", nameof(allowedOrigins));
        }

        AllowedOrigins = allowedOrigins;
    }

    public AuthenticationCeremonyOriginParameters(Uri[] origins)
    {
        ArgumentNullException.ThrowIfNull(origins);
        if (origins.Length == 0)
        {
            throw new ArgumentException($"The {nameof(origins)} must contain at least one element", nameof(origins));
        }

        var result = new string[origins.Length];
        for (var i = 0; i < origins.Length; i++)
        {
            var baseUri = origins[i];
            if (!baseUri.IsAbsoluteUri)
            {
                throw new ArgumentException($"The {nameof(origins)}[{i}] element contains a non-absolute Uri. Unable to obtain origin.", nameof(origins));
            }

            if (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps)
            {
                throw new ArgumentException($"The {nameof(origins)}[{i}] element contains an invalid request scheme. Only '{Uri.UriSchemeHttp}' and '{Uri.UriSchemeHttps}' are allowed.", nameof(origins));
            }

            var resultOrigin = baseUri.IsDefaultPort
                ? $"{baseUri.Scheme}://{baseUri.Host}"
                : $"{baseUri.Scheme}://{baseUri.Host}:{baseUri.Port}";
            result[i] = resultOrigin;
        }

        AllowedOrigins = result;
    }

    public string[] AllowedOrigins { get; }

    public static AuthenticationCeremonyOriginParameters Create(Uri[] origins)
    {
        return new(origins);
    }
}
