namespace WebAuthn.Net.Services.Metrics.Implementation.Constants;

/// <summary>
///     Constants with metrics tag values.
/// </summary>
public static class TagValues
{
    /// <summary>
    ///     Successful operation status.
    /// </summary>
    public const string StatusSuccess = "ok";

    /// <summary>
    ///     Failed operation status
    /// </summary>
    public const string StatusFail = "fail";

    /// <summary>
    ///     An element was skipped because an error occurred during its processing.
    /// </summary>
    public const string ReasonException = "exception";

    /// <summary>
    ///     A FIDO Metadata Service blob was rejected because it would roll back the metadata in use to an older blob.
    /// </summary>
    public const string ReasonRollback = "rollback";

    /// <summary>
    ///     The anomaly was tolerated: the data was accepted despite it.
    /// </summary>
    public const string OutcomeTolerated = "tolerated";

    /// <summary>
    ///     The anomaly caused the data to be rejected.
    /// </summary>
    public const string OutcomeRejected = "rejected";
}
