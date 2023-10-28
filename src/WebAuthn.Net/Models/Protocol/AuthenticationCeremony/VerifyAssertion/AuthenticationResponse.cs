using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;

public class AuthenticationResponse
{
    public AuthenticationResponse(
        byte[] id,
        byte[] rawId,
        AuthenticatorAssertionResponse response,
        AuthenticatorAttachment? authenticatorAttachment,
        AuthenticationExtensionsClientOutputs? clientExtensionResults,
        PublicKeyCredentialType type)
    {
        Id = id;
        RawId = rawId;
        Response = response;
        AuthenticatorAttachment = authenticatorAttachment;
        ClientExtensionResults = clientExtensionResults;
        Type = type;
    }

    public byte[] Id { get; }

    public byte[] RawId { get; }

    public AuthenticatorAssertionResponse Response { get; }

    public AuthenticatorAttachment? AuthenticatorAttachment { get; }

    public AuthenticationExtensionsClientOutputs? ClientExtensionResults { get; }

    public PublicKeyCredentialType Type { get; }
}
