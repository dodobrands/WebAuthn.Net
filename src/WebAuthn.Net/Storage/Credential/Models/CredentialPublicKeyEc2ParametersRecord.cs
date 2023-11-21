using WebAuthn.Net.Services.Serialization.Cose.Models.Enums.EC2;

namespace WebAuthn.Net.Storage.Credential.Models;

public class CredentialPublicKeyEc2ParametersRecord
{
    public CredentialPublicKeyEc2ParametersRecord(CoseEc2EllipticCurve crv, byte[] x, byte[] y)
    {
        Crv = crv;
        X = x;
        Y = y;
    }

    public CoseEc2EllipticCurve Crv { get; }
    public byte[] X { get; }
    public byte[] Y { get; }
}
