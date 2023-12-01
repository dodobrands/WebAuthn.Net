using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;

/// <summary>
///     Decoder of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a> into a typed representation.
/// </summary>
public interface IFidoU2FAttestationStatementDecoder
{
    /// <summary>
    ///     Decodes <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a> from <see cref="CborMap" /> into <see cref="FidoU2FAttestationStatement" />.
    /// </summary>
    /// <param name="attStmt">CBOR representation of <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-fido-u2f-attestation">FIDO U2F attestation statement</a>.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="FidoU2FAttestationStatement" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<FidoU2FAttestationStatement> Decode(CborMap attStmt);
}
