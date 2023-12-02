using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

public interface ITpmManufacturerVerifier
{
    Result<byte[][]> IsValid(string tpmManufacturer);
}
