using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;

public class FidoMetadataResult
{
    public FidoMetadataResult(byte[][] rootCertificates, AuthenticatorAttestationType[] attestationTypes)
    {
        RootCertificates = rootCertificates;
        AttestationTypes = attestationTypes;
    }

    public byte[][] RootCertificates { get; }

    public AuthenticatorAttestationType[] AttestationTypes { get; }
}
