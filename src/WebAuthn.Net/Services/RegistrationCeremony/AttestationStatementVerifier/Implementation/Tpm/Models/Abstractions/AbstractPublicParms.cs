using System;
using System.Diagnostics.CodeAnalysis;
using WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.Tpm.Models.Enums;

namespace WebAuthn.Net.Services.RegistrationCeremony.Implementation.Verification.Tpm.Models.Abstractions;

/// <summary>
///     12.2.3.4 TPMS_ASYM_PARMS
/// </summary>
public abstract class AbstractPublicParms
{
    public static bool TryParse(
        ref Span<byte> buffer,
        TpmAlgPublic type,
        ObjectAttributes objectAttributes,
        [NotNullWhen(true)] out AbstractPublicParms? parameters)
    {
        // 12.2.3.4 TPMS_ASYM_PARMS
        // This structure contains the common public area parameters for an asymmetric key.
        // The first two parameters of the parameter definition structures of an asymmetric key shall have the same two first components.
        // Table 195 — Definition of TPMS_ASYM_PARMS Structure <>
        // | Parameter | Type                 | Description
        // | symmetric | TPMT_SYM_DEF_OBJECT+ | The companion symmetric algorithm for a restricted decryption key and shall be set to a supported symmetric algorithm. This field is optional for keys that are not decryption keys and shall be set to TPM_ALG_NULL if not used.
        // | scheme    | TPMT_ASYM_SCHEME+    | For a key with the sign attribute SET, a valid signing scheme for the key type
        // |           |                      | For a key with the decrypt attribute SET, a valid key exchange protocol.
        // |           |                      | For a key with sign and decrypt attributes, shall be TPM_ALG_NULL.
        // The symmetric and scheme properties vary for RSA and ECC
        switch (type)
        {
            case TpmAlgPublic.Rsa:
                {
                    if (RsaParms.TryParseRsaParms(ref buffer, objectAttributes, out var rsaParms))
                    {
                        parameters = rsaParms;
                        return true;
                    }

                    parameters = null;
                    return false;
                }
            case TpmAlgPublic.Ecc:
                {
                    if (EccParms.TryParseEccParms(ref buffer, objectAttributes, out var eccParms))
                    {
                        parameters = eccParms;
                        return true;
                    }

                    parameters = null;
                    return false;
                }
            default:
                {
                    parameters = null;
                    return false;
                }
        }
    }
}
