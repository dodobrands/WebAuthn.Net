using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

namespace WebAuthn.Net.Demo.FidoConformance.Services;

public class ConformanceTpmManufacturerVerifier : DefaultTpmManufacturerVerifier
{
    public override Result<UniqueByteArraysCollection?> IsValid(string tpmManufacturer)
    {
        var baseResult = base.IsValid(tpmManufacturer);
        if (baseResult.HasError)
        {
            // The FIDO Conformance Tools use the vendor identifier id:FFFFF1D0, which is not in the TCG TPM Vendor ID Registry.
            // It is matched exactly as the tools send it (the base class matches the hexadecimal digits of registered vendors case-insensitively).
            if (tpmManufacturer == "id:FFFFF1D0")
            {
                return Result<UniqueByteArraysCollection?>.Success(new(TpmRoots.Microsoft));
            }
        }

        return baseResult;
    }
}
