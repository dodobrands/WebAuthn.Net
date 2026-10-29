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
    ///     The reason why an element was skipped or rejected, or why an operation failed.
    /// </summary>
    public const string Reason = "reason";

    /// <summary>
    ///     The value of the 'status' member of a status report of the FIDO Metadata Service blob.
    /// </summary>
    public const string AuthenticatorStatus = "authenticator_status";

    /// <summary>
    ///     The path of a member of the FIDO Metadata Service blob: of its payload or of an entry.
    /// </summary>
    public const string Member = "member";

    /// <summary>
    ///     The attestation statement format identifier.
    /// </summary>
    public const string AttestationStatementFormat = "fmt";

    /// <summary>
    ///     An anomaly found while decoding or verifying an attestation statement or a response of a ceremony.
    /// </summary>
    public const string Anomaly = "anomaly";

    /// <summary>
    ///     The outcome of an anomaly: whether it was tolerated or caused a rejection.
    /// </summary>
    public const string Outcome = "outcome";

    /// <summary>
    ///     The source of the FIDO Metadata Service blob: embedded in the application or downloaded from the FIDO Metadata Service.
    /// </summary>
    public const string Source = "source";
}
