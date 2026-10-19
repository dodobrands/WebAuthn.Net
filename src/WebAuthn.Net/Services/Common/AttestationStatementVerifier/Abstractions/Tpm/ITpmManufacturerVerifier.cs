using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

/// <summary>
///     Verifier of the TPM module manufacturer named in the AIK certificate of a <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement</a>.
/// </summary>
public interface ITpmManufacturerVerifier
{
    /// <summary>
    ///     Checks whether the TPM manufacturer identifier from the AIK certificate's Subject Alternative Name is known.
    ///     The identifier is the TPMManufacturer attribute (OID 2.23.133.2.1) in the form "id:XXXXXXXX" - "id:" followed by the 4-byte vendor ID as 8 uppercase hexadecimal digits -
    ///     as defined by the TCG EK Credential Profile §3.1.2, with the vendor IDs assigned in the TCG TPM Vendor ID Registry.
    /// </summary>
    /// <param name="tpmManufacturer">The TPMManufacturer attribute value, e.g. "id:414D4400" (AMD).</param>
    /// <returns>
    ///     A successful result with the manufacturer's embedded root CA certificates (may be <see langword="null" /> or empty; additional trust anchors come from the FIDO Metadata Service) when the manufacturer is known;
    ///     a failed result when it is unknown.
    /// </returns>
    Result<UniqueByteArraysCollection?> IsValid(string tpmManufacturer);
}
