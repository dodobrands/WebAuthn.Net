using WebAuthn.Net.Mysql.Infrastructure;

namespace WebAuthn.Net.Mysql.Repositories;

public class MysqlRegistrationCeremonyRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public MysqlRegistrationCeremonyRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }
}
