using Microsoft.Extensions.DependencyInjection;
using WebAuthn.Net.Storage.SqlServer.Configuration.Options;
using WebAuthn.Net.Storage.SqlServer.Models;

namespace WebAuthn.Net.Storage.SqlServer.Configuration.Builder;

public class SqlServerWebAuthnBuilder<TContext> : ISqlServerWebAuthnBuilder<TContext>
    where TContext : DefaultSqlServerContext
{
    public SqlServerWebAuthnBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public ISqlServerWebAuthnBuilder<TContext> AddSqlServerCoreServices(Action<DefaultSqlServerContext>? configure = null)
    {
        Services.AddOptions<SqlServerOptions>();
        if (configure is not null)
        {
            Services.Configure(configure);
        }

        return this;
    }
}
