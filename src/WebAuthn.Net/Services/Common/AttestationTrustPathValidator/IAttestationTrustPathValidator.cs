using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;

namespace WebAuthn.Net.Services.Common.AttestationTrustPathValidator;

/// <summary>
///     <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">Attestation trust path</a> validator. It validates that the attestation statement is trustworthy.
/// </summary>
public interface IAttestationTrustPathValidator
{
    /// <summary>
    ///     Validates the <a href="https://www.w3.org/TR/webauthn-3/#attestation-trust-path">attestation trust path</a>.
    /// </summary>
    /// <param name="verificationResult">Artifact of a successfully verified attestation statement.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns><see langword="true" />, if verificationResult contains a valid attestation trust path, otherwise - <see langword="false" /></returns>
    Task<bool> IsValidAsync(VerifiedAttestationStatement verificationResult, CancellationToken cancellationToken);
}
