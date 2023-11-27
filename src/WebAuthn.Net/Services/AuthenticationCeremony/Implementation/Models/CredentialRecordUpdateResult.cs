using WebAuthn.Net.Storage.Credential.Models;

namespace WebAuthn.Net.Services.AuthenticationCeremony.Implementation.Models;

public class CredentialRecordUpdateResult
{
    public CredentialRecordUpdateResult(CredentialRecord updatedCredentialRecord, bool uvInitializedCanBeUpdatedToTrue)
    {
        UpdatedCredentialRecord = updatedCredentialRecord;
        UvInitializedCanBeUpdatedToTrue = uvInitializedCanBeUpdatedToTrue;
    }

    public CredentialRecord UpdatedCredentialRecord { get; }

    public bool UvInitializedCanBeUpdatedToTrue { get; }
}
