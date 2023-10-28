namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony.VerifyAssertion;

public class AuthenticatorAssertionResponse
{
    public AuthenticatorAssertionResponse(
        byte[] clientDataJson,
        byte[] authenticatorData,
        byte[] signature,
        byte[]? userHandle,
        byte[]? attestationObject)
    {
        ClientDataJson = clientDataJson;
        AuthenticatorData = authenticatorData;
        Signature = signature;
        UserHandle = userHandle;
        AttestationObject = attestationObject;
    }

    public byte[] ClientDataJson { get; }

    public byte[] AuthenticatorData { get; }

    public byte[] Signature { get; }

    public byte[]? UserHandle { get; }

    public byte[]? AttestationObject { get; }
}
