// using System;
// using System.Threading;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Http;
// using WebAuthn.Net.Models;
// using WebAuthn.Net.Models.Abstractions;
// using WebAuthn.Net.Models.Protocol.AuthenticationCeremony;
// using WebAuthn.Net.Services.AuthenticationCeremony.Models;
// using WebAuthn.Net.Services.Context;
//
// namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation;
//
// public class DefaultAuthenticationCeremonyService<TContext> : IAuthenticationCeremonyService
//     where TContext : class, IWebAuthnContext
// {
//     private readonly IWebAuthnContextFactory<TContext> _contextFactory;
//
//     public DefaultAuthenticationCeremonyService(IWebAuthnContextFactory<TContext> contextFactory)
//     {
//         ArgumentNullException.ThrowIfNull(contextFactory);
//         _contextFactory = contextFactory;
//     }
//
//     public async Task<CredentialRequestOptions> CreateOptionsAsync(
//         HttpContext httpContext,
//         CredentialRequestOptionsRequest request,
//         CancellationToken cancellationToken)
//     {
//         cancellationToken.ThrowIfCancellationRequested();
//         await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
//         throw new NotImplementedException();
//     }
//
//     public async Task<Result<AuthenticationCeremonyResponse>> HandleAsync(
//         HttpContext httpContext,
//         AuthenticationCeremonyRequest request,
//         CancellationToken cancellationToken)
//     {
//         cancellationToken.ThrowIfCancellationRequested();
//         await using var context = await _contextFactory.CreateAsync(httpContext, cancellationToken);
//         throw new NotImplementedException();
//     }
// }



