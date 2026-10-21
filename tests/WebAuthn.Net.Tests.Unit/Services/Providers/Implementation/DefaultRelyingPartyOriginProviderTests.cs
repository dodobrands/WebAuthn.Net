using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using NUnit.Framework;

namespace WebAuthn.Net.Services.Providers.Implementation;

// The default origin is the ASCII serialization of the origin of the current request (RFC 6454, section 6.2) - the way the client reports it.
public class DefaultRelyingPartyOriginProviderTests
{
    [TestCase("https", "example.org", "https://example.org")]
    [TestCase("https", "Example.ORG:443", "https://example.org")]
    [TestCase("https", "example.org:8443", "https://example.org:8443")]
    [TestCase("http", "localhost:5000", "http://localhost:5000")]
    [TestCase("https", "пример.рф", "https://xn--e1afmkfd.xn--p1ai")]
    public async Task DefaultRelyingPartyOriginProvider_ReturnsOriginOfCurrentRequest(string scheme, string host, string expectedOrigin)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Scheme = scheme;
        httpContext.Request.Host = new(host);
        httpContext.Request.PathBase = "/app";

        var origin = await new DefaultRelyingPartyOriginProvider().GetAsync(httpContext, CancellationToken.None);

        Assert.That(origin, Is.EqualTo(expectedOrigin));
    }
}
