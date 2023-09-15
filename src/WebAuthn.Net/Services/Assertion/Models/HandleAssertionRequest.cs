using System;
using WebAuthn.Net.Models.Protocol.Assertion;

namespace WebAuthn.Net.Services.Assertion.Models;

public class HandleAssertionRequest
{
    public HandleAssertionRequest(PublicKeyCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        Credential = credential;
    }

    public PublicKeyCredential Credential { get; }
}
