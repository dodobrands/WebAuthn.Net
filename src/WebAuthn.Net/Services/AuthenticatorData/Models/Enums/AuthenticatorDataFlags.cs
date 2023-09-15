using System;

namespace WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

[Flags]
public enum AuthenticatorDataFlags : byte
{
    UserPresent = 1,

    // Bit 1: Reserved for future use (RFU1).
    UserVerified = 4,

    // Bits 3-5: Reserved for future use (RFU2).
    AttestedCredentialData = 64,
    ExtensionDataIncluded = 128
}
