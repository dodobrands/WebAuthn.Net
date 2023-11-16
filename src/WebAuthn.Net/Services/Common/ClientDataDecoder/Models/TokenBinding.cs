using System;
using System.ComponentModel;
using WebAuthn.Net.Services.Common.ClientDataDecoder.Models.Enums;

namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Models;

public class TokenBinding
{
    public TokenBinding(TokenBindingStatus status, byte[]? id)
    {
        if (!Enum.IsDefined(typeof(TokenBindingStatus), status))
        {
            throw new InvalidEnumArgumentException(nameof(status), (int) status, typeof(TokenBindingStatus));
        }

        if (status == TokenBindingStatus.Present)
        {
            if (id is null)
            {
                ArgumentNullException.ThrowIfNull(id);
            }

            if (id.Length == 0)
            {
                throw new ArgumentException($"The {nameof(id)} must contain at least one element", nameof(id));
            }
        }

        Status = status;
        Id = id;
    }

    public TokenBindingStatus Status { get; }

    public byte[]? Id { get; }
}
