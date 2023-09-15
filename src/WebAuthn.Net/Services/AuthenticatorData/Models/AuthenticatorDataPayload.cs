using System;
using System.Collections.Generic;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Models;

public class AuthenticatorDataPayload
{
    public byte[] RpIdHash { get; }
    public IReadOnlySet<AuthenticatorDataFlags> Flags { get; }
    public uint SignCount { get; }

    public AuthenticatorDataPayload()
    {
        RpIdHash = Array.Empty<byte>();
        Flags = new HashSet<AuthenticatorDataFlags>(0);
        SignCount = 0;
    }
}
