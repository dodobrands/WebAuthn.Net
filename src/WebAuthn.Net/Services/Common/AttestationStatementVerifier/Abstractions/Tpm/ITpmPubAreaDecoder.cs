using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

/// <summary>
///     Decoder of the TPMT_PUBLIC structure, defined in the <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (section 12.2.4)</a>, from binary into a typed representation.
/// </summary>
public interface ITpmPubAreaDecoder
{
    /// <summary>
    ///     Decodes the TPMT_PUBLIC structure from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="bytes">Binary representation of the TPMT_PUBLIC structure.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="PubArea" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<PubArea> Decode(Span<byte> bytes);
}
