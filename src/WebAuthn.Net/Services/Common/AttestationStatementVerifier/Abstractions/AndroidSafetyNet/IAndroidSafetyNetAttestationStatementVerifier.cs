using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;

/// <summary>
///     Verifier of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public interface IAndroidSafetyNetAttestationStatementVerifier<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Asynchronously verifies the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attStmt">
    ///     Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
    /// </param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="clientDataHash">SHA256 hash of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-authenticatorresponse-clientdatajson">clientDataJSON</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the verification is successful - the result containing <see cref="VerifiedAttestationStatement" />, otherwise - the result indicating that the validation has failed.</returns>
    Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        AndroidSafetyNetAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken);
}
