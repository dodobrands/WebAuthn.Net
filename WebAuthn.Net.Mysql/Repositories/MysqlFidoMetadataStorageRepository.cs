using WebAuthn.Net.Mysql.Infrastructure;

namespace WebAuthn.Net.Mysql.Repositories;

public class MysqlFidoMetadataStorageRepository
{
    private readonly IDbConnectionFactory _connectionFactory;

    public MysqlFidoMetadataStorageRepository(IDbConnectionFactory connectionFactory)
    {
        _connectionFactory = connectionFactory;
    }
}
