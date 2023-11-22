using System;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Models.Attestation;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmPubAreaDecoder
{
    Result<PubArea> Decode(Span<byte> bytes);
}
