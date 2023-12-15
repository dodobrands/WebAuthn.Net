using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Services.Context;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeWebAuthnContextFactory : IWebAuthnContextFactory<FakeWebAuthnContext>
{
    private readonly List<FakeWebAuthnContextMetrics> _metrics = new();

    public Task<FakeWebAuthnContext> CreateAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metrics = new FakeWebAuthnContextMetrics();
        _metrics.Add(metrics);
        var fakeContext = new FakeWebAuthnContext(httpContext, metrics);
        return Task.FromResult(fakeContext);
    }

    public FakeWebAuthnContextMetrics[] GetMetrics()
    {
        return _metrics.ToArray();
    }

    public void ResetMetrics()
    {
        foreach (var metric in _metrics)
        {
            metric.Reset();
        }
    }
}
