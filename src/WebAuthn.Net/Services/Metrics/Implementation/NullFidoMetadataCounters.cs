namespace WebAuthn.Net.Services.Metrics.Implementation;

/// <summary>
///     <see cref="IFidoMetadataCounters" /> that counts nothing, for the services constructed without metrics.
/// </summary>
internal sealed class NullFidoMetadataCounters : IFidoMetadataCounters
{
    public static NullFidoMetadataCounters Instance { get; } = new();

    public void IncrementDownloadStart()
    {
    }

    public void IncrementDownloadEnd(bool successful)
    {
    }

    public void IncrementDownloadFailure(string reason)
    {
    }

    public void IncrementDecodeStart()
    {
    }

    public void IncrementDecodeEnd(bool successful)
    {
    }

    public void IncrementEntrySkipped(string member)
    {
    }

    public void IncrementEntrySkippedDueToException()
    {
    }

    public void IncrementStatusReportIgnored(string status)
    {
    }

    public void IncrementValueIgnored(string member)
    {
    }

    public void IncrementBlobRejectedDueToRollback()
    {
    }

    public void IncrementLookupWithoutMetadata()
    {
    }

    public void IncrementLookupWithUntrustedEntry()
    {
    }
}
