using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Attestation;
using WebAuthn.Net.Services.Attestation.Models;
using WebAuthn.Net.Services.Context;

namespace WebAuthn.Net.Services.Attestation.Implementations;

public class AttestationService<TContext> : IAttestationService
    where TContext : class, IWebAuthnContext
{
    private readonly IWebAuthnContextFactory<TContext> _contextFactory;

    public AttestationService(IWebAuthnContextFactory<TContext> contextFactory)
    {
        ArgumentNullException.ThrowIfNull(contextFactory);
        _contextFactory = contextFactory;
    }

    public async Task<CredentialCreationOptions> CreateOptionsAsync(
        HttpContext httpContext,
        CredentialCreationOptionsRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        throw new NotImplementedException();
    }

    public async Task<Result<HandleAttestationResponse>> HandleAsync(
        HttpContext httpContext,
        HandleAttestationRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        throw new NotImplementedException();
    }
}
