using System;
using NUnit.Framework;

namespace WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions;

// https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-origin
// The client reports the ASCII serialization of an origin (RFC 6454, section 6.2), so the expected origins are compared with it as is.
public class RegistrationCeremonyOriginParametersTests
{
    [TestCase("https://example.org", "https://example.org")]
    [TestCase("https://Example.ORG:443/path?query#fragment", "https://example.org")]
    [TestCase("https://example.org:8443/", "https://example.org:8443")]
    [TestCase("http://localhost:5000", "http://localhost:5000")]
    [TestCase("https://пример.рф", "https://xn--e1afmkfd.xn--p1ai")]
    [TestCase("https://Bücher.example:8443", "https://xn--bcher-kva.example:8443")]
    [TestCase("http://127.0.0.1:5000", "http://127.0.0.1:5000")]
    [TestCase("http://[::1]:5000", "http://[::1]:5000")]
    public void RegistrationCeremonyOriginParameters_SerializesOriginsTheWayTheClientReportsThem(string address, string expectedOrigin)
    {
        var parameters = new RegistrationCeremonyOriginParameters(new[] { new Uri(address, UriKind.Absolute) });

        Assert.That(parameters.AllowedOrigins, Is.EqualTo(new[] { expectedOrigin }));
    }
}
