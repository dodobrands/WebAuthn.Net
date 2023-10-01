﻿using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.AuthenticationCeremony;
using WebAuthn.Net.Services.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation;
using WebAuthn.Net.Services.TimeProvider;
using WebAuthn.Net.Services.TimeProvider.Implementation;

namespace WebAuthn.Net.Configuration.Builder;

public class WebAuthnBuilder<TContext> : IWebAuthnBuilder<TContext>
    where TContext : class, IWebAuthnContext
{
    public WebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IWebAuthnBuilder<TContext> AddCoreServices(Action<WebAuthnOptions>? configure = null)
    {
        Services.AddOptions<WebAuthnOptions>();
        if (configure is not null)
        {
            Services.Configure(configure);
        }

        Services.TryAddSingleton<IAuthenticationCeremonyService, DefaultAuthenticationCeremonyService<TContext>>();
        Services.TryAddSingleton<IAuthenticatorDataDecoder, DefaultAuthenticatorDataDecoder>();
        Services.TryAddSingleton<IChallengeGenerator, DefaultChallengeGenerator>();
        Services.TryAddSingleton<IRegistrationCeremonyService, DefaultRegistrationCeremonyService<TContext>>();
        Services.TryAddSingleton<ITimeProvider, DefaultTimeProvider>();
        return this;
    }
}
