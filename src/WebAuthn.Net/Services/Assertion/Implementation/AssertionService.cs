using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Assertion;
using WebAuthn.Net.Services.Assertion.Models;
using WebAuthn.Net.Services.Context;

namespace WebAuthn.Net.Services.Assertion.Implementation;

public class AssertionService<TContext> : IAssertionService
    where TContext : class, IWebAuthnContext
{
    private readonly IWebAuthnContextFactory<TContext> _contextFactory;

    public AssertionService(IWebAuthnContextFactory<TContext> contextFactory)
    {
        ArgumentNullException.ThrowIfNull(contextFactory);
        _contextFactory = contextFactory;
    }

    public async Task<CredentialRequestOptions> CreateOptionsAsync(
        HttpContext httpContext,
        CredentialRequestOptionsRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        throw new NotImplementedException();
    }

    public async Task<Result<HandleAssertionResponse>> HandleAsync(
        HttpContext httpContext,
        HandleAssertionRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        throw new NotImplementedException();
    }
}
