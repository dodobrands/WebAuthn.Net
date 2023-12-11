using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;

/// <summary>
///     Search result in metadata from the FIDO Metadata Service.
/// </summary>
public class FidoMetadataResult
{
    /// <summary>
    ///     Constructs <see cref="FidoMetadataResult" />.
    /// </summary>
    /// <param name="rootCertificates">x509v3 root CA certificates from the FIDO Metadata Service.</param>
    /// <param name="attestationTypes">
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attestation-types">Authenticator attestation types</a>
    /// </param>
    public FidoMetadataResult(byte[][] rootCertificates, AuthenticatorAttestationType[] attestationTypes)
    {
        RootCertificates = rootCertificates;
        AttestationTypes = attestationTypes;
    }

    /// <summary>
    ///     x509v3 root CA certificates from the FIDO Metadata Service.
    /// </summary>
    public byte[][] RootCertificates { get; }

    /// <summary>
    ///     <a href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-ps-20220523.html#authenticator-attestation-types">Authenticator attestation types</a>
    /// </summary>
    public AuthenticatorAttestationType[] AttestationTypes { get; }
}
