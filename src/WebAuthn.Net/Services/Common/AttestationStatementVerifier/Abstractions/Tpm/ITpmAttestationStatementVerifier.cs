using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

/// <summary>
///     Verifier of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement</a> (WebAuthn Level 3 §8.3 "TPM Attestation Statement Format"),
///     including the <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements">TPM Attestation Statement Certificate Requirements</a> (§8.3.1).
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface ITpmAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Asynchronously verifies the <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement</a> by performing the verification procedure of WebAuthn Level 3 §8.3.
    ///     The first step of that procedure (CBOR decoding of attStmt and conformance to the tpmStmtFormat syntax) is performed by the attestation statement decoder that produced <paramref name="attStmt" />.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attStmt">Decoded <a href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">TPM attestation statement</a>.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="clientDataHash">SHA256 hash of <a href="https://www.w3.org/TR/webauthn-3/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the verification is successful - the result containing <see cref="VerifiedAttestationStatement" />, otherwise - the result indicating that the validation has failed.</returns>
    Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        TpmAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken);
}
