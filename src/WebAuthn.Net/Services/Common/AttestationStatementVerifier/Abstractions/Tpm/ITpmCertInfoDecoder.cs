using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm.Models.Attestation;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmCertInfoDecoder
{
    Result<CertInfo> Decode(Span<byte> bytes);
}
