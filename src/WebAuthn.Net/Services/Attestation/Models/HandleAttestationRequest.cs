using System;
using WebAuthn.Net.Models.Protocol.Attestation;

namespace WebAuthn.Net.Services.Attestation.Models;

public class HandleAttestationRequest
{
    public HandleAttestationRequest(PublicKeyCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        Credential = credential;
    }

    public PublicKeyCredential Credential { get; }
}
