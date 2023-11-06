using System;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateOptions;

namespace WebAuthn.Net.Storage.RegistrationCeremony.Models;

public class RegistrationCeremonyParameters
{
    public RegistrationCeremonyParameters(
        PublicKeyCredentialCreationOptions options,
        RegistrationCeremonyRpParameters expectedRp,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
    {
        Options = options;
        ExpectedRp = expectedRp;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public PublicKeyCredentialCreationOptions Options { get; }
    public RegistrationCeremonyRpParameters ExpectedRp { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }
}
