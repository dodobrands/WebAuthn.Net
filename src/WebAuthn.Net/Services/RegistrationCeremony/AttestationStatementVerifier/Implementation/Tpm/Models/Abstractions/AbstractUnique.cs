using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.Tpm.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.Tpm.Models.Abstractions;

/// <summary>
///     12.2.3.2 TPMU_PUBLIC_ID
/// </summary>
public abstract class AbstractUnique
{
    public static bool TryParse(
        ref Span<byte> buffer,
        TpmAlgPublic type,
        [NotNullWhen(true)] out AbstractUnique? unique)
    {
        // 12.2.3.2 TPMU_PUBLIC_ID
        // This is the union of all values allowed in in the unique field of a TPMT_PUBLIC
        // Table 193 — Definition of TPMU_PUBLIC_ID Union <IN/OUT>
        // | Parameter | Type                 | Selector          | Description
        // | keyedHash | TPM2B_DIGEST         | TPM_ALG_KEYEDHASH |
        // | sym       | TPM2B_DIGEST         | TPM_ALG_SYMCIPHER |
        // | rsa       | TPM2B_PUBLIC_KEY_RSA | TPM_ALG_RSA       |
        // | ecc       | TPMS_ECC_POINT       | TPM_ALG_ECC       |
        // | derive    | TPMS_DERIVE          |                   | only allowed for TPM2_CreateLoaded when parentHandle is a Derivation Parent.
        switch (type)
        {
            case TpmAlgPublic.Rsa:
                {
                    if (RsaUnique.TryParseRsaUnique(ref buffer, out var rsaUnique))
                    {
                        unique = rsaUnique;
                        return true;
                    }

                    unique = null;
                    return false;
                }
            case TpmAlgPublic.Ecc:
                {
                    if (EccUnique.TryParseEccUnique(ref buffer, out var eccUnique))
                    {
                        unique = eccUnique;
                        return true;
                    }

                    unique = null;
                    return false;
                }
            default:
                {
                    unique = null;
                    return false;
                }
        }
    }
}
