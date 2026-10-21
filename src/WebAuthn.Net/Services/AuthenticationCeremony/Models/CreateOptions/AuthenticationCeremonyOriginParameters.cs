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
    /// <param name="allowedOrigins">
    ///     Origins for the authentication ceremony. Cannot be <see langword="null" /> and must contain at least one element. They are compared with the origins from the client data by exact string matching, so each one has to be written the way the client reports it: the
    ///     serialization of an origin (for example, <c>https://example.org</c> or <c>https://xn--e1afmkfd.xn--p1ai</c> - lowercase, without a path or a trailing slash, with the port only if it isn't the default one) or the origin of a native application.
    /// </param>
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
    /// <param name="allowedOrigins">
    ///     Addresses whose origins are allowed for the authentication ceremony. Cannot be <see langword="null" /> and must contain at least one element. Only the scheme, the host and the port of each address are used: they are serialized the way the client reports an origin,
    ///     with an internationalized domain name in its ASCII (Punycode) form and without the default port.
    /// </param>
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

            // https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin
            // The client reports the ASCII serialization of an origin (RFC 6454, section 6.2), where an internationalized domain name is in its Punycode form.
            // 'Uri.Host' returns such a name in Unicode, while 'Uri.IdnHost' returns an IPv6 address without the brackets the serialization needs.
            var host = baseUri.HostNameType == UriHostNameType.IPv6
                ? baseUri.Host
                : baseUri.IdnHost;
            var resultOrigin = baseUri.IsDefaultPort
                ? $"{baseUri.Scheme}://{host}"
                : $"{baseUri.Scheme}://{host}:{baseUri.Port}";
            result[i] = resultOrigin;
        }

        AllowedOrigins = result;
    }

    /// <summary>
    ///     Allowed origins.
    /// </summary>
    public string[] AllowedOrigins { get; }
}
