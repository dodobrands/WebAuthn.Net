## Adding a migration

To add a migration, navigate to the WebAuthn.Net.Storage.MySql.Migrations project directory:

```bash
cd src/WebAuthn.Net.Storage.MySql.Migrations
```

Execute one of the following commands for the DbContext to which you need to add a migration

### MySqlCredentialStorageDbContext

```bash
dotnet ef migrations add --context MySqlCredentialStorageDbContext --output-dir "Storage/CredentialStorage/Migrations" InitialCreate
```

## Dump migrations to an SQL file

### MySqlCredentialStorageDbContext

```bash
dotnet ef migrations script --context MySqlCredentialStorageDbContext --output "Storage/CredentialStorage/RawMigrations.sql"
```
