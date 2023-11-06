using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Storage.Credential;
using WebAuthn.Net.Storage.Credential.Models;
using WebAuthn.Net.Storage.MySql.Models;

namespace WebAuthn.Net.Storage.MySql.Storage.CredentialStorage;

public class DefaultMySqlCredentialStorage<TContext> : ICredentialStorage<TContext>
    where TContext : DefaultMySqlContext
{
    public async Task<PublicKeyCredentialDescriptor[]?> FindDescriptorsAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();
        var result = new List<PublicKeyCredentialDescriptor>();
        var dbPublicKeys = await context.Connection.QueryAsync<MySqlPublicKeyCredentialDescriptor>(
            new(
                "SELECT `Type`, `CredentialId`, `Transports` FROM `UserCredentials` WHERE `RpId` = @rpId AND `UserHandle` = @userHandle;",
                new
                {
                    rpId,
                    userHandle
                },
                context.Transaction,
                cancellationToken: cancellationToken));

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (dbPublicKeys is null)
        {
            return Array.Empty<PublicKeyCredentialDescriptor>();
        }

        foreach (var dbPublicKey in dbPublicKeys)
        {
            result.Add(dbPublicKey.ToResultModel());
        }

        return result.ToArray();
    }


    public Task<UserCredentialRecord?> FindCredentialAsync(
        TContext context,
        string rpId,
        byte[] userHandle,
        byte[] credentialId,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<bool> SaveIfNotRegisteredForOtherUserAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<bool> UpdateCredentialAsync(
        TContext context,
        UserCredentialRecord credential,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    [SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes")]
    private class MySqlPublicKeyCredentialDescriptor
    {
        public MySqlPublicKeyCredentialDescriptor(int type, byte[] credentialId, string transports)
        {
            Type = type;
            CredentialId = credentialId;
            Transports = transports;
        }

        public int Type { get; }

        public byte[] CredentialId { get; }

        public string Transports { get; }

        public PublicKeyCredentialDescriptor ToResultModel()
        {
            var type = (PublicKeyCredentialType) Type;
            var transports = Array.Empty<AuthenticatorTransport>();
            if (!string.IsNullOrEmpty(Transports))
            {
                var deserializedTransports = JsonSerializer.Deserialize<int[]>(Transports);
                if (deserializedTransports?.Length > 0)
                {
                    transports = deserializedTransports.Select(x => (AuthenticatorTransport) x).ToArray();
                }
            }

            return new(
                type,
                CredentialId,
                transports);
        }
    }
}
