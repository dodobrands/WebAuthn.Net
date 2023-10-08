namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.Tpm.Models;

/// <summary>
///     7.1 TPM_HANDLE
/// </summary>
public class TpmHandle
{
    public TpmHandle(uint handle)
    {
        Handle = handle;
    }

    // 7 Handles
    // 7.1 Introduction
    // Handles are 32-bit values used to reference shielded locations of various types within the TPM.
    // Table 26 — Definition of Types for Handles
    // | Type   | Name       | Description
    // | UINT32 | TPM_HANDLE |

    public uint Handle { get; }
}
