using System;
using WebAuthn.Net.Services.RegistrationCeremony.Models.CreateOptions.Protocol;

namespace WebAuthn.Net.Storage.Operations.Models;

public class RegistrationCeremonyOptions
{
    public RegistrationCeremonyOptions(
        PublicKeyCredentialCreationOptions options,
        string expectedOrigin,
        string[] expectedTopOrigins,
        DateTimeOffset createdAt,
        DateTimeOffset? expiresAt)
    {
        Options = options;
        ExpectedOrigin = expectedOrigin;
        ExpectedTopOrigins = expectedTopOrigins;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    public PublicKeyCredentialCreationOptions Options { get; }
    public string ExpectedOrigin { get; }
    public string[] ExpectedTopOrigins { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset? ExpiresAt { get; }
}
