using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Services.Context;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeWebAuthnContextFactory : IWebAuthnContextFactory<FakeWebAuthnContext>
{
    public Task<FakeWebAuthnContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var fakeContext = new FakeWebAuthnContext(httpContext);
        return Task.FromResult(fakeContext);
    }
}
