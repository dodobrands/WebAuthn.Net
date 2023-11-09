using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Configuration.DependencyInjection;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Storage.AuthenticationCeremony.Implementation;
using WebAuthn.Net.Storage.InMemory.Configuration.Builder;
using WebAuthn.Net.Storage.InMemory.Models;
using WebAuthn.Net.Storage.InMemory.Services.ContextFactory;
using WebAuthn.Net.Storage.InMemory.Storage.CredentialStorage;
using WebAuthn.Net.Storage.RegistrationCeremony.Implementation;

namespace WebAuthn.Net.Storage.InMemory.Configuration.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IInMemoryWebAuthnBuilder<DefaultInMemoryContext> AddWebAuthnInMemory(
        this IServiceCollection services,
        Action<DefaultCookieRegistrationCeremonyStorageOptions>? configureRegistration = null,
        Action<DefaultCookieAuthenticationCeremonyStorageOptions>? configureAuthentication = null,
        Action<WebAuthnOptions>? configureCore = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        services
            .AddWebAuthnCore<DefaultInMemoryContext>(configureCore)
            .AddDefaultStorages(configureRegistration, configureAuthentication)
            .AddContextFactory<DefaultInMemoryContext, DefaultInMemoryContextFactory>()
            .AddCredentialStorage<DefaultInMemoryContext, DefaultInMemoryCredentialStorage<DefaultInMemoryContext>>();
        return new InMemoryWebAuthnBuilder<DefaultInMemoryContext>(services);
    }
}
