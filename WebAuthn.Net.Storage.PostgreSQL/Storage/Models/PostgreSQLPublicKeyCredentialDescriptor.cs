using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Storage.Postgres.Storage.Models;

[SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes")]
public class PostgreSqlPublicKeyCredentialDescriptor
{
    public PostgreSqlPublicKeyCredentialDescriptor(int type, byte[] credentialId, int[] transports, long createdAtUnixTime)
    {
        Type = type;
        CredentialId = credentialId;
        Transports = transports;
        CreatedAtUnixTime = createdAtUnixTime;
    }

    public int Type { get; }

    public byte[] CredentialId { get; }

    public int[] Transports { get; }

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
        if (Transports.Length > 0)
        {
            transports = new AuthenticatorTransport[Transports.Length];
            for (var i = 0; i < Transports.Length; i++)
            {
                var transport = (AuthenticatorTransport) Transports[i];
                if (!Enum.IsDefined(transport))
                {
                    return false;
                }

                transports[i] = transport;
            }
        }

        result = new(type, CredentialId, transports);
        return true;
    }
}
