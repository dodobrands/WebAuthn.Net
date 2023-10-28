namespace WebAuthn.Net.Storage.Credential.Models;

public class CredentialPublicKeyRsaParametersRecord
{
    public CredentialPublicKeyRsaParametersRecord(byte[] modulusN, byte[] exponentE)
    {
        ModulusN = modulusN;
        ExponentE = exponentE;
    }

    public byte[] ModulusN { get; }
    public byte[] ExponentE { get; }
}
