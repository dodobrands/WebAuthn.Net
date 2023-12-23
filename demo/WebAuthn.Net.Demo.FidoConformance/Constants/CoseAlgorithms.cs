using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Demo.FidoConformance.Constants;

public static class CoseAlgorithms
{
    public static readonly CoseAlgorithm[] All =
    {
        CoseAlgorithm.RS1,
        CoseAlgorithm.RS512,
        CoseAlgorithm.RS384,
        CoseAlgorithm.RS256,
        CoseAlgorithm.PS512,
        CoseAlgorithm.PS384,
        CoseAlgorithm.PS256,
        CoseAlgorithm.ES512,
        CoseAlgorithm.ES384,
        CoseAlgorithm.ES256,
        CoseAlgorithm.EdDSA
    };
}
