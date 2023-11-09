using System;
using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Configuration.Builder;

public class MySqlWebAuthnBuilder<TContext> : IMySqlWebAuthnBuilder<TContext>
    where TContext : DefaultMySqlContext
{
    public MySqlWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
