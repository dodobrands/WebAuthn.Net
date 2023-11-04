using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Services.Providers;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeRelyingPartyIdProvider : IRelyingPartyIdProvider
{
    private readonly Uri _relyingPartyAddress;

    public FakeRelyingPartyIdProvider(Uri relyingPartyAddress)
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
        var effectiveDomain = _relyingPartyAddress.Host;
        return Task.FromResult(effectiveDomain);
    }
}
