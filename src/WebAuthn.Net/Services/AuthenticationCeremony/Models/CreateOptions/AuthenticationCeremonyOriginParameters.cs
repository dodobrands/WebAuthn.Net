using System;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Models.CreateOptions;

/// <summary>
///     Parameters of origins for the authentication ceremony.
/// </summary>
public class AuthenticationCeremonyOriginParameters
{
    /// <summary>
    ///     Constructs <see cref="AuthenticationCeremonyOriginParameters" />.
    /// </summary>
    /// <param name="allowedOrigins">Origins for the authentication ceremony. Cannot be <see langword="null" /> and must contain at least one element.</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedOrigins" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="allowedOrigins" /> is empty</exception>
    public AuthenticationCeremonyOriginParameters(string[] allowedOrigins)
    {
        ArgumentNullException.ThrowIfNull(allowedOrigins);
        if (allowedOrigins.Length == 0)
        {
            throw new ArgumentException($"The {nameof(allowedOrigins)} must contain at least one element", nameof(allowedOrigins));
        }

        AllowedOrigins = allowedOrigins;
    }

    /// <summary>
    ///     Constructs <see cref="AuthenticationCeremonyOriginParameters" />.
    /// </summary>
    /// <param name="allowedOrigins">Origins for the authentication ceremony. Cannot be <see langword="null" /> and must contain at least one element.</param>
    /// <exception cref="ArgumentNullException"><paramref name="allowedOrigins" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="allowedOrigins" /> is empty</exception>
    /// <exception cref="ArgumentException">One of the <paramref name="allowedOrigins" /> elements contains a non-absolute Uri</exception>
    /// <exception cref="ArgumentException">One of the <paramref name="allowedOrigins" /> elements contains an invalid scheme</exception>
    public AuthenticationCeremonyOriginParameters(Uri[] allowedOrigins)
    {
        ArgumentNullException.ThrowIfNull(allowedOrigins);
        if (allowedOrigins.Length == 0)
        {
            throw new ArgumentException($"The {nameof(allowedOrigins)} must contain at least one element", nameof(allowedOrigins));
        }

        var result = new string[allowedOrigins.Length];
        for (var i = 0; i < allowedOrigins.Length; i++)
        {
            var baseUri = allowedOrigins[i];
            if (!baseUri.IsAbsoluteUri)
            {
                throw new ArgumentException($"The {nameof(allowedOrigins)}[{i}] element contains a non-absolute Uri. Unable to obtain origin.", nameof(allowedOrigins));
            }

            if (baseUri.Scheme != Uri.UriSchemeHttp && baseUri.Scheme != Uri.UriSchemeHttps)
            {
                throw new ArgumentException($"The {nameof(allowedOrigins)}[{i}] element contains an invalid request scheme. Only '{Uri.UriSchemeHttp}' and '{Uri.UriSchemeHttps}' are allowed.", nameof(allowedOrigins));
            }

            var resultOrigin = baseUri.IsDefaultPort
                ? $"{baseUri.Scheme}://{baseUri.Host}"
                : $"{baseUri.Scheme}://{baseUri.Host}:{baseUri.Port}";
            result[i] = resultOrigin;
        }

        AllowedOrigins = result;
    }

    /// <summary>
    ///     Allowed origins.
    /// </summary>
    public string[] AllowedOrigins { get; }
}
