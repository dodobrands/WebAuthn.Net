using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.OKP;

namespace WebAuthn.Net.Storage.Credential.Models;

public class CredentialPublicKeyOkpParametersRecord
{
    public CredentialPublicKeyOkpParametersRecord(CoseOkpEllipticCurve crv, byte[] x)
    {
        Crv = crv;
        X = x;
    }

    public CoseOkpEllipticCurve Crv { get; }
    public byte[] X { get; }
}
