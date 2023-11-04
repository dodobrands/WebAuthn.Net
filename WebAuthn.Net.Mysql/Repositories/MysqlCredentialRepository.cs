using WebAuthn.Net.Mysql.Infrastructure;

namespace WebAuthn.Net.Mysql.Repositories;

public class MysqlCredentialRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public MysqlCredentialRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }
}
