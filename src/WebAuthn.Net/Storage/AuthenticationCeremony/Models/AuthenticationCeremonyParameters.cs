using System;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Storage.Models;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Models;

public class AuthenticationCeremonyParameters
{
    public AuthenticationCeremonyParameters(
        byte[]? userHandle,
        PublicKeyCredentialRequestOptions options,
        ExpectedRpParameters expectedRp,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        UserHandle = userHandle;
        Options = options;
        ExpectedRp = expectedRp;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public byte[]? UserHandle { get; }
    public PublicKeyCredentialRequestOptions Options { get; }
    public ExpectedRpParameters ExpectedRp { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
}
