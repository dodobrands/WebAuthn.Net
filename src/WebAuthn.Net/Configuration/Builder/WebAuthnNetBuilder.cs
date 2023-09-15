using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Services.AuthenticatorData;
using WebAuthn.Net.Services.AuthenticatorData.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation;
using WebAuthn.Net.Services.TimeProvider;
using WebAuthn.Net.Services.TimeProvider.Implementation;

namespace WebAuthn.Net.Configuration.Builder;

public class WebAuthnNetBuilder<TContext> : IWebAuthnNetBuilder<TContext>
    where TContext : class, IWebAuthnContext
{
    public WebAuthnNetBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IWebAuthnNetBuilder<TContext> AddCoreServices()
    {
        Services.TryAddSingleton<IAuthenticationCeremonyService, DefaultAuthenticationCeremonyService<TContext>>();
        Services.TryAddSingleton<IAuthenticatorDataService, DefaultAuthenticatorDataService>();
        Services.TryAddSingleton<IChallengeGenerator, DefaultChallengeGenerator>();
        Services.TryAddSingleton<IRegistrationCeremonyService, DefaultRegistrationCeremonyService<TContext>>();
        Services.TryAddSingleton<ITimeProvider, DefaultTimeProvider>();
        return this;
    }
}
