using System.Collections.Generic;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;

public class AuthenticationResponse
{
    public AuthenticationResponse(
        byte[] id,
        byte[] rawId,
        AuthenticatorAssertionResponse response,
        AuthenticatorAttachment? authenticatorAttachment,
        Dictionary<string, JsonElement> clientExtensionResults,
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

    public Dictionary<string, JsonElement> ClientExtensionResults { get; }

    public PublicKeyCredentialType Type { get; }
}
