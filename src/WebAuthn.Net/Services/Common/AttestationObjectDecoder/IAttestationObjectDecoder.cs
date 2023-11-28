using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;

namespace WebAuthn.Net.Services.Common.AttestationObjectDecoder;

/// <summary>
///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">attestationObject</a> from binary into a typed representation.
/// </summary>
public interface IAttestationObjectDecoder
{
    /// <summary>
    ///     Decodes the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">attestationObject</a> from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="attestationObject">Binary representation of the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">attestationObject</a>.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AttestationObject" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<AttestationObject> Decode(byte[] attestationObject);
}
