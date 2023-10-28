using System;

namespace WebAuthn.Net.Storage.Credential.Models;

public class UserCredentialRecord
{
    public UserCredentialRecord(byte[] userHandle, string rpId, CredentialRecord credentialRecord)
    {
        UserHandle = userHandle;
        RpId = rpId;
        CredentialRecord = credentialRecord;
    }

    public byte[] UserHandle { get; }

    public string RpId { get; }

    public CredentialRecord CredentialRecord { get; }

    public bool ContainsCredentialThatBelongsTo(string rpId, byte[] userHandle, byte[] credentialId)
    {
        return rpId == RpId
               && userHandle.AsSpan().SequenceEqual(UserHandle.AsSpan())
               && credentialId.AsSpan().SequenceEqual(CredentialRecord.Id.AsSpan());
    }
}
