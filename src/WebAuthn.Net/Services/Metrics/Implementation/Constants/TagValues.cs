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
}
