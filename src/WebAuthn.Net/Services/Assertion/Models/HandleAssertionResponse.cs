namespace WebAuthn.Net.Services.Assertion.Models;

public class HandleAssertionResponse
{
    public HandleAssertionResponse(byte[] credentialId)
    {
        CredentialId = credentialId;
    }

    public byte[] CredentialId { get; }
}
