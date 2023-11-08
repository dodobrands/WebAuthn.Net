using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.Postgres.Configuration.Options;
using WebAuthn.Net.Storage.Postgres.Models;

namespace WebAuthn.Net.Storage.Postgres.Configuration.Builder;

public class PostgreSqlWebAuthnBuilder<TContext> : IPostgreSqlWebAuthnBuilder<TContext>
    where TContext : DefaultPostgreSqlContext
{
    public PostgreSqlWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IPostgreSqlWebAuthnBuilder<TContext> AddPostgreSqlCoreServices(Action<DefaultPostgreSqlContext>? configure = null)
    {
        Services.AddOptions<PostgreSqlOptions>();
        if (configure is not null)
        {
            Services.Configure(configure);
        }

        return this;
    }
}
