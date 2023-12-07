using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

/// <summary>
///     Decoder of the TPMS_ATTEST structure over which the above signature was computed, as specified in <a href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2: Structures specification (section 10.12.12)</a>.
/// </summary>
public interface ITpmCertInfoDecoder
{
    /// <summary>
    ///     Decodes the TPMS_ATTEST structure from binary representation to a typed format for further processing.
    /// </summary>
    /// <param name="bytes">Binary representation of the TPMT_PUBLIC structure.</param>
    /// <returns>If the decoding was successful, the result contains the <see cref="CertInfo" />; otherwise, the result indicates that an error occurred during the decoding process.</returns>
    Result<CertInfo> Decode(Span<byte> bytes);
}
