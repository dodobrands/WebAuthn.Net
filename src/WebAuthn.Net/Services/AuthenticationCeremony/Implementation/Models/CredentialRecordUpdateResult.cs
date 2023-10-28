using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.Models;

public class CredentialRecordUpdateResult
{
    public CredentialRecordUpdateResult(CredentialRecord updatedCredentialRecord, bool uvInitializedUpdated)
    {
        UpdatedCredentialRecord = updatedCredentialRecord;
        UvInitializedUpdated = uvInitializedUpdated;
    }

    public CredentialRecord UpdatedCredentialRecord { get; }

    public bool UvInitializedUpdated { get; }
}
