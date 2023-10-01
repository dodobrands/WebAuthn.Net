using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.Tpm.Models.Enums.Extensions;

public static class TpmAlgIdHashExtensions
{
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms")]
    public static bool TryComputeHash(this TpmAlgIdHash tpmAlg, byte[] message, [NotNullWhen(true)] out byte[]? hash)
    {
        switch (tpmAlg)
        {
            case TpmAlgIdHash.Sha1:
                {
                    hash = SHA1.HashData(message);
                    return true;
                }
            case TpmAlgIdHash.Sha256:
                {
                    hash = SHA256.HashData(message);
                    return true;
                }
            case TpmAlgIdHash.Sha384:
                {
                    hash = SHA384.HashData(message);
                    return true;
                }
            case TpmAlgIdHash.Sha512:
                {
                    hash = SHA512.HashData(message);
                    return true;
                }
            default:
                {
                    hash = null;
                    return false;
                }
        }
    }
}
