namespace WebAuthn.Net.Services.Serialization.Cbor.CredentialPublicKey.Models;

public class CredentialPublicKeyDecodeResult
{
    public CredentialPublicKeyDecodeResult(DecodedCredentialPublicKey credentialPublicKey, int bytesConsumed)
    {
        CredentialPublicKey = credentialPublicKey;
        BytesConsumed = bytesConsumed;
    }

    public DecodedCredentialPublicKey CredentialPublicKey { get; }

    public int BytesConsumed { get; }
}
