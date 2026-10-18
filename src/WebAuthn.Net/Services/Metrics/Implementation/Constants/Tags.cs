namespace WebAuthn.Net.Services.Metrics.Implementation.Constants;

/// <summary>
///     Constants with metrics tags.
/// </summary>
public static class Tags
{
    /// <summary>
    ///     Operation status.
    /// </summary>
    public const string Status = "status";

    /// <summary>
    ///     The reason why an element was skipped.
    /// </summary>
    public const string Reason = "reason";

    /// <summary>
    ///     The value of the 'status' member of a status report of the FIDO Metadata Service blob.
    /// </summary>
    public const string AuthenticatorStatus = "authenticator_status";

    /// <summary>
    ///     The path of a member of an entry of the FIDO Metadata Service blob.
    /// </summary>
    public const string Member = "member";
}
