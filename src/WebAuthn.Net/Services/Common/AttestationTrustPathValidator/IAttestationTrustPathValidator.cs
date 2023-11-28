using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator;

/// <summary>
///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-trust-path">Attestation trust path</a> validator. It validates that the attestation statement is trustworthy.
/// </summary>
public interface IAttestationTrustPathValidator
{
    /// <summary>
    ///     Validates the attestation trust path.
    /// </summary>
    /// <param name="verificationResult"></param>
    /// <returns></returns>
    bool IsValid(VerifiedAttestationStatement verificationResult);
}
