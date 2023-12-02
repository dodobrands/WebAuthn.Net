using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.Tpm.Constants;

namespace WebAuthn.Net.FidoConformance.Services;

public class ConformanceTpmManufacturerVerifier : DefaultTpmManufacturerVerifier
{
    public override Result<byte[][]> IsValid(string tpmManufacturer)
    {
        var baseResult = base.IsValid(tpmManufacturer);
        if (baseResult.HasError)
        {
            if (tpmManufacturer == "id:FFFFF1D0")
            {
                return Result<byte[][]>.Success(TpmRoots.Microsoft);
            }
        }

        return baseResult;
    }
}
