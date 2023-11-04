using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Services.Providers;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeRelyingPartyOriginProvider : IRelyingPartyOriginProvider
{
    private readonly Uri _relyingPartyAddress;

    public FakeRelyingPartyOriginProvider(Uri relyingPartyAddress)
    {
        ArgumentNullException.ThrowIfNull(relyingPartyAddress);
        if (!relyingPartyAddress.IsAbsoluteUri)
        {
            throw new ArgumentException("An absolute URI is required", nameof(relyingPartyAddress));
        }

        _relyingPartyAddress = relyingPartyAddress;
    }

    public Task<string> GetAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = _relyingPartyAddress.IsDefaultPort
            ? $"{_relyingPartyAddress.Scheme}://{_relyingPartyAddress.Host}"
            : $"{_relyingPartyAddress.Scheme}://{_relyingPartyAddress.Host}:{_relyingPartyAddress.Port}";
        return Task.FromResult(result);
    }
}
