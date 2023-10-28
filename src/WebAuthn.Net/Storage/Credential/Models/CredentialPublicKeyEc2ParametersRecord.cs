using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Storage.Credential.Models;

public class CredentialPublicKeyEc2ParametersRecord
{
    public CredentialPublicKeyEc2ParametersRecord(CoseEllipticCurve crv, byte[] x, byte[] y)
    {
        Crv = crv;
        X = x;
        Y = y;
    }

    public CoseEllipticCurve Crv { get; }
    public byte[] X { get; }
    public byte[] Y { get; }
}
