using System;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;
using WebAuthn.Net.Storage.Models;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Models;

public class RegistrationCeremonyParameters
{
    public RegistrationCeremonyParameters(
        PublicKeyCredentialCreationOptions options,
        ExpectedRpParameters expectedRp,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        Options = options;
        ExpectedRp = expectedRp;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public PublicKeyCredentialCreationOptions Options { get; }
    public ExpectedRpParameters ExpectedRp { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
}
