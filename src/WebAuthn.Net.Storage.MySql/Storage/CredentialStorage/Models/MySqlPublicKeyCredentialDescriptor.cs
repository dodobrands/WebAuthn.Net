using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Storage.MySql.Storage.CredentialStorage.Models;

[SuppressMessage("Design", "CA1812:Avoid uninstantiated internal classes")]
public class MySqlPublicKeyCredentialDescriptor
{
    public MySqlPublicKeyCredentialDescriptor(int type, byte[] credentialId, string transports, long createdAtUnixTime)
    {
        Type = type;
        CredentialId = credentialId;
        Transports = transports;
        CreatedAtUnixTime = createdAtUnixTime;
    }

    public int Type { get; }

    [Required]
    [MaxLength(1024)]
    public byte[] CredentialId { get; }

    [Column(TypeName = "json")]
    [Required]
    public string Transports { get; }

    public long CreatedAtUnixTime { get; }

    public virtual bool TryToPublicKeyCredentialDescriptor([NotNullWhen(true)] out PublicKeyCredentialDescriptor? result)
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
            var transportsIntegers = JsonSerializer.Deserialize<int[]>(Transports);
            if (transportsIntegers?.Length > 0)
            {
                var typedTransports = transportsIntegers
                    .Select(x => (AuthenticatorTransport) x)
                    .ToArray();
                foreach (var authenticatorTransport in typedTransports)
                {
                    if (!Enum.IsDefined(authenticatorTransport))
                    {
                        return false;
                    }
                }

                transports = typedTransports;
            }
        }

        result = new(type, CredentialId, transports);
        return true;
    }
}
