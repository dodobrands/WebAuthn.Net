using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Storage.MySql.Models;

[SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes")]
internal class MySqlPublicKeyCredentialDescriptor
{
    public MySqlPublicKeyCredentialDescriptor(int type, byte[] credentialId, string transports, long createdAtUnixTime)
    {
        Type = type;
        CredentialId = credentialId;
        Transports = transports;
        CreatedAtUnixTime = createdAtUnixTime;
    }

    public int Type { get; }

    public byte[] CredentialId { get; }

    public string Transports { get; }

    public long CreatedAtUnixTime { get; }

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
