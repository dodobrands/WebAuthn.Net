using System.Collections.Generic;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Models;

public class AuthenticatorDataPayload
{
    public AuthenticatorDataPayload(byte[] rpIdHash, IReadOnlySet<AuthenticatorDataFlags> flags, uint signCount)
    {
        RpIdHash = rpIdHash;
        Flags = flags;
        SignCount = signCount;
    }

    public byte[] RpIdHash { get; }
    public IReadOnlySet<AuthenticatorDataFlags> Flags { get; }
    public uint SignCount { get; }
}
