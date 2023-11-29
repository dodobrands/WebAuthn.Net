using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions;

/// <summary>
///     Decoder for <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> from CBOR into a typed representation.
/// </summary>
public interface IAttestationStatementDecoder
{
    /// <summary>
    ///     Decodes the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#attestation-statement">attestation statement</a> from CBOR into a typed one for further work.
    /// </summary>
    /// <param name="attStmt">CBOR representation of the attestation statement.</param>
    /// <param name="attestationStatementFormat">The value of "fmt" obtained from the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#fig-attStructs">attestationObject</a>. Determines how the <paramref name="attStmt" /> will be interpreted.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="AbstractAttestationStatement" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<AbstractAttestationStatement> Decode(CborMap attStmt, AttestationStatementFormat attestationStatementFormat);
}
