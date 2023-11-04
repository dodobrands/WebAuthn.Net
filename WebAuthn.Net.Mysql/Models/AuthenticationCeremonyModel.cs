using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Models.Protocol.AuthenticationCeremony.CreateOptions;
using WebAuthn.Net.Storage.AuthenticationCeremony.Models;
using WebAuthn.Net.Storage.Models;

namespace WebAuthn.Net.Mysql.Models;

public class AuthenticationCeremonyModel
{
    public AuthenticationCeremonyModel(string id, byte[]? userHandle, PublicKeyCredentialRequestOptions options, ExpectedRpParameters expectedRp, DateTimeOffset createdAt, DateTimeOffset expiresAt)
    {
        Id = id;
        UserHandle = userHandle;
        Options = options;
        ExpectedRp = expectedRp;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }
    public string Id { get; }
    public byte[]? UserHandle { get; }
    public PublicKeyCredentialRequestOptions Options { get; }
    public ExpectedRpParameters ExpectedRp { get; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset ExpiresAt { get; }

    public static AuthenticationCeremonyModel FromAuthenticationCeremonyParameters(AuthenticationCeremonyParameters parameters, string id)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        return new(id, parameters.UserHandle, parameters.Options, parameters.ExpectedRp, parameters.CreatedAt, parameters.ExpiresAt);
    }

    public AuthenticationCeremonyParameters ToAuthenticationCeremonyParameters() =>
        new(UserHandle, Options, ExpectedRp, CreatedAt, ExpiresAt);
}
