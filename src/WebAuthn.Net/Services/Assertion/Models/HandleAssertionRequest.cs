using WebAuthn.Net.Models.Protocol.Assertion;

namespace WebAuthn.Net.Services.Assertion.Models;

public class HandleAssertionRequest
{
    public HandleAssertionRequest(PublicKeyCredential credential)
    {
        Credential = credential;
    }

    public PublicKeyCredential Credential { get; }
}
