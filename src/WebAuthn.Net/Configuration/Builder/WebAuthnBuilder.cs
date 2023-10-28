using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Implementation;
using WebAuthn.Net.Services.Common.ChallengeGenerator;
using WebAuthn.Net.Services.Common.ChallengeGenerator.Implementation;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Providers.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation;

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

        Services.TryAddSingleton<IAuthenticatorDataDecoder, DefaultAuthenticatorDataDecoder>();
        Services.TryAddSingleton<IChallengeGenerator, DefaultChallengeGenerator>();
        Services.TryAddSingleton<IRegistrationCeremonyService, DefaultRegistrationCeremonyService<TContext>>();
        Services.TryAddSingleton<ITimeProvider, DefaultTimeProvider>();
        return this;
    }
}
