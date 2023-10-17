using System;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.Providers;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeRelyingPartyIdProvider : IRelyingPartyIdProvider<FakeWebAuthnContext>
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

    public Task<string> GetAsync(FakeWebAuthnContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var effectiveDomain = _relyingPartyAddress.Host;
        return Task.FromResult(effectiveDomain);
    }
}
