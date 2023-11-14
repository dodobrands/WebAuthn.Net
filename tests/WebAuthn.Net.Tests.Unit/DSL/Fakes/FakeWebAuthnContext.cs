using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models.Abstractions;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeWebAuthnContext : IWebAuthnContext
{
    public FakeWebAuthnContext(HttpContext? httpContext, FakeWebAuthnContextMetrics metrics)
    {
        HttpContext = httpContext!;
        Metrics = metrics;
    }

    private FakeWebAuthnContextMetrics Metrics { get; }

    public HttpContext HttpContext { get; }

    public ValueTask DisposeAsync()
    {
        GC.SuppressFinalize(this);
        return ValueTask.CompletedTask;
    }

    public Task CommitAsync(CancellationToken cancellationToken)
    {
        Metrics.Commits++;
        return Task.CompletedTask;
    }
}
