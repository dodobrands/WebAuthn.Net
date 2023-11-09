using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Storage.SqlServer.Storage.Models;

[SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes")]
public class SqlServerPublicKeyCredentialDescriptor
{
    public SqlServerPublicKeyCredentialDescriptor(int type, byte[] credentialId, string transports, long createdAtUnixTime)
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

    public bool TryMapToResult([NotNullWhen(true)] out PublicKeyCredentialDescriptor? result)
    {
        result = null;
        var type = (PublicKeyCredentialType) Type;
        if (!Enum.IsDefined(type))
        {
            return false;
        }

        var transports = Array.Empty<AuthenticatorTransport>();
        if (!string.IsNullOrEmpty(Transports))
        {
            var deserializedTransports = JsonSerializer.Deserialize<int[]>(Transports);
            if (deserializedTransports?.Length > 0)
            {
                transports = new AuthenticatorTransport[deserializedTransports.Length];
                for (var i = 0; i < deserializedTransports.Length; i++)
                {
                    var transport = (AuthenticatorTransport) deserializedTransports[i];
                    if (!Enum.IsDefined(transport))
                    {
                        return false;
                    }

                    transports[i] = transport;
                }
            }
        }

        result = new(type, CredentialId, transports);
        return true;
    }
}
