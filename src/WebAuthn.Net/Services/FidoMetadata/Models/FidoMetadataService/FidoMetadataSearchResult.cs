namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;

public class FidoMetadataSearchResult
{
    public FidoMetadataSearchResult(byte[][] rootCertificates)
    {
        RootCertificates = rootCertificates;
    }

    public byte[][] RootCertificates { get; }
}
