using System;
using WebAuthn.Net.Models.Protocol.RegistrationCeremony;

namespace WebAuthn.Net.Storage.Operations.Models;

public class RegistrationCeremonyOptions
{
    public RegistrationCeremonyOptions(CredentialCreationOptions options, DateTimeOffset createdAt, DateTimeOffset? expiresAt)
    {
        Options = options;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public CredentialCreationOptions Options { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset? ExpiresAt { get; }
}
