namespace WebAuthn.Net.Configuration.Options;

public class WebAuthnOptions
{
    public AttestationStatementOptions AttestationStatements { get; set; } = new();
    public AttestationTypeOptions AttestationTypes { get; set; } = new();
    public X509ChainValidationOptions X509ChainValidation { get; set; } = new();
    public FidoMetadataOptions FidoMetadata { get; set; } = new();
}
