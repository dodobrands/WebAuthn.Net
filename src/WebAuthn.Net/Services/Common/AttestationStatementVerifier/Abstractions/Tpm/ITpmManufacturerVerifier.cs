using WebAuthn.Net.Models;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.Tpm;

/// <summary>
///     Verifier of TPM module manufacturer.
/// </summary>
public interface ITpmManufacturerVerifier
{
    /// <summary>
    /// </summary>
    /// <param name="tpmManufacturer"></param>
    /// <returns></returns>
    Result<UniqueByteArraysCollection?> IsValid(string tpmManufacturer);
}
