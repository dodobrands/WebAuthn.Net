namespace WebAuthn.Net.Storage.Operations.Models;

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
