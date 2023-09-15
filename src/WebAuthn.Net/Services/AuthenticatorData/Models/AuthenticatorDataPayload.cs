using System;
using System.Collections.Generic;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Models;

public class AuthenticatorDataPayload
{
    public byte[] RpIdHash { get; }
    public IReadOnlySet<AuthenticatorDataFlags> Flags { get; }
    public uint SignCount { get; }

    public AuthenticatorDataPayload(byte[] rpIdHash, IReadOnlySet<AuthenticatorDataFlags> flags)
    {
        RpIdHash = rpIdHash;
        Flags = flags;
        SignCount = 0;
    }
}
