using System;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;

/// <summary>
///     Decoded <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
/// </summary>
public class AndroidSafetyNetAttestationStatement : AbstractAttestationStatement
{
    /// <summary>
    ///     Constructs <see cref="AndroidSafetyNetAttestationStatement" />.
    /// </summary>
    /// <param name="ver">The version number of Google Play Services responsible for providing the SafetyNet API.</param>
    /// <param name="response">
    ///     The UTF-8 encoded result of the getJwsResult() call of the SafetyNet API. This value is a JWS <a href="https://www.rfc-editor.org/rfc/rfc7515.html">[RFC7515]</a> object (see
    ///     <a href="https://developer.android.com/training/safetynet/attestation#compat-check-response">SafetyNet online documentation</a>) in Compact Serialization.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="ver" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="ver" /> is empty</exception>
    /// <exception cref="ArgumentNullException"><paramref name="response" /> is <see langword="null" /></exception>
    public AndroidSafetyNetAttestationStatement(string ver, byte[] response)
    {
        // ver
        ArgumentNullException.ThrowIfNull(ver);
        if (string.IsNullOrEmpty(ver))
        {
            throw new ArgumentException("Value cannot be null or empty.", nameof(ver));
        }

        Ver = ver;

        // response
        ArgumentNullException.ThrowIfNull(response);
        Response = response;
    }

    /// <summary>
    ///     The version number of Google Play Services responsible for providing the SafetyNet API.
    /// </summary>
    public string Ver { get; }

    /// <summary>
    ///     The UTF-8 encoded result of the getJwsResult() call of the SafetyNet API. This value is a JWS <a href="https://www.rfc-editor.org/rfc/rfc7515.html">[RFC7515]</a> object (see
    ///     <a href="https://developer.android.com/training/safetynet/attestation#compat-check-response">SafetyNet online documentation</a>) in Compact Serialization.
    /// </summary>
    public byte[] Response { get; }
}
