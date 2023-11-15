using System.Collections.Generic;
using System.Text.Json;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony.CreateCredential;

public class RegistrationResponse
{
    public RegistrationResponse(
        byte[] id,
        byte[] rawId,
        AuthenticatorAttestationResponse response,
        AuthenticatorAttachment? authenticatorAttachment,
        Dictionary<string, JsonElement>? clientExtensionResults,
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
    public AuthenticatorAttestationResponse Response { get; }
    public AuthenticatorAttachment? AuthenticatorAttachment { get; }
    public Dictionary<string, JsonElement>? ClientExtensionResults { get; }
    public PublicKeyCredentialType Type { get; }
}
