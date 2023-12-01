using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;

/// <summary>
///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a> into a typed representation.
/// </summary>
public interface IAndroidSafetyNetAttestationStatementDecoder
{
    /// <summary>
    ///     Decodes <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a> from <see cref="CborMap" /> into <see cref="AndroidSafetyNetAttestationStatement" />.
    /// </summary>
    /// <param name="attStmt">
    ///     CBOR representation of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
    /// </param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AndroidSafetyNetAttestationStatement" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<AndroidSafetyNetAttestationStatement> Decode(CborMap attStmt);
}
