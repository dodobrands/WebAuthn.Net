using System;

namespace WebAuthn.Net.Storage.Credential.Models;

/// <summary>
///     Credential record bound to a user account.
/// </summary>
public class UserCredentialRecord
{
    /// <summary>
    ///     Constructs <see cref="UserCredentialRecord" />.
    /// </summary>
    /// <param name="userHandle">Unique user account identifier to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.</param>
    /// <param name="rpId">The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.</param>
    /// <param name="description">Description of the credential.</param>
    /// <param name="credentialRecord">
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">Credential Record</a>
    /// </param>
    public UserCredentialRecord(byte[] userHandle, string rpId, string? description, CredentialRecord credentialRecord)
    {
        UserHandle = userHandle;
        RpId = rpId;
        Description = description;
        CredentialRecord = credentialRecord;
    }

    /// <summary>
    ///     Unique user account identifier to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.
    /// </summary>
    public byte[] UserHandle { get; }

    /// <summary>
    ///     The <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#rp-id">RP ID</a> to which the <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">credential record</a> is bound.
    /// </summary>
    public string RpId { get; }

    /// <summary>
    ///     Description of the credential.
    /// </summary>
    public string? Description { get; }

    /// <summary>
    ///     <a href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#credential-record">Credential Record</a>
    /// </summary>
    public CredentialRecord CredentialRecord { get; }

    /// <summary>
    ///     Verifies whether the current object actually stores the credential data that belongs to the specified parameters
    /// </summary>
    /// <param name="rpId">The RP ID being verified.</param>
    /// <param name="userHandle">The user handle being verified.</param>
    /// <param name="credentialId">The credentialId being verified.</param>
    /// <returns><see langword="true" /> if the data matches, otherwise - <see langword="false" />.</returns>
    public bool ContainsCredentialThatBelongsTo(string rpId, byte[] userHandle, byte[] credentialId)
    {
        return rpId == RpId
               && userHandle.AsSpan().SequenceEqual(UserHandle.AsSpan())
               && credentialId.AsSpan().SequenceEqual(CredentialRecord.Id.AsSpan());
    }
}
