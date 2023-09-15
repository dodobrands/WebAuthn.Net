using WebAuthn.Net.Models.Protocol;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Services.Assertion.Models;

public class CredentialRequestOptionsRequest
{
    public CredentialRequestOptionsRequest(
        CredentialMediationRequirement? mediation,
        uint? timeout,
        string? rpId,
        PublicKeyCredentialDescriptor[]? allowCredentials,
        UserVerificationRequirement? userVerification,
        AuthenticationExtensionsClientInputs? extensions)
    {
        Mediation = mediation;
        Timeout = timeout;
        RpId = rpId;
        AllowCredentials = allowCredentials;
        UserVerification = userVerification;
        Extensions = extensions;
    }

    public CredentialMediationRequirement? Mediation { get; }

    public uint? Timeout { get; }

    public string? RpId { get; }

    public PublicKeyCredentialDescriptor[]? AllowCredentials { get; }

    public UserVerificationRequirement? UserVerification { get; }

    public AuthenticationExtensionsClientInputs? Extensions { get; }

    public static CredentialRequestOptionsRequest Passkeys()
    {
        return new(
            null,
            null,
            null,
            null,
            null,
            null);
    }
}
