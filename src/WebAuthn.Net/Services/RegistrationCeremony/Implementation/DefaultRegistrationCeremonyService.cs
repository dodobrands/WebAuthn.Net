using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;
using WebAuthn.Net.Services.Context;
using WebAuthn.Net.Services.RegistrationCeremony.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation;

public class DefaultRegistrationCeremonyService<TContext> : IRegistrationCeremonyService
    where TContext : class, IWebAuthnContext
{
    private readonly IWebAuthnContextFactory<TContext> _contextFactory;

    public DefaultRegistrationCeremonyService(IWebAuthnContextFactory<TContext> contextFactory)
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

    public async Task<Result<RegistrationCeremonyResult>> HandleAsync(
        HttpContext httpContext,
        RegistrationCeremonyRequest request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
        throw new NotImplementedException();
    }
}
