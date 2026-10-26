using System.Collections.Generic;
using WebAuthn.Net.Services.Metrics;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeFidoMetadataCounters : IFidoMetadataCounters
{
    private readonly List<string> _downloadFailures = new();
    private readonly List<string> _embeddedLoadFailures = new();
    private readonly List<string> _ignoredStatusReports = new();
    private readonly List<string> _ignoredValues = new();
    private readonly List<string> _ingestExceptions = new();
    private readonly List<string> _skippedEntries = new();

    public int DownloadStarts { get; private set; }

    public int SuccessfulDownloadEnds { get; private set; }

    public int FailedDownloadEnds { get; private set; }

    public IReadOnlyList<string> DownloadFailures => _downloadFailures;

    public int EmbeddedLoadStarts { get; private set; }

    public int SuccessfulEmbeddedLoadEnds { get; private set; }

    public int FailedEmbeddedLoadEnds { get; private set; }

    public IReadOnlyList<string> EmbeddedLoadFailures => _embeddedLoadFailures;

    public IReadOnlyList<string> IngestExceptions => _ingestExceptions;

    public int DecodeStarts { get; private set; }

    public int SuccessfulDecodeEnds { get; private set; }

    public int FailedDecodeEnds { get; private set; }

    public IReadOnlyList<string> SkippedEntries => _skippedEntries;

    public IReadOnlyList<string> IgnoredStatusReports => _ignoredStatusReports;

    public IReadOnlyList<string> IgnoredValues => _ignoredValues;

    public int BlobsRejectedDueToRollback { get; private set; }

    public int LookupsWithoutMetadata { get; private set; }

    public int LookupsWithUntrustedEntry { get; private set; }

    public void IncrementDownloadStart()
    {
        DownloadStarts++;
    }

    public void IncrementDownloadEnd(bool successful)
    {
        if (successful)
        {
            SuccessfulDownloadEnds++;
        }
        else
        {
            FailedDownloadEnds++;
        }
    }

    public void IncrementDownloadFailure(string reason)
    {
        _downloadFailures.Add(reason);
    }

    public void IncrementEmbeddedLoadStart()
    {
        EmbeddedLoadStarts++;
    }

    public void IncrementEmbeddedLoadEnd(bool successful)
    {
        if (successful)
        {
            SuccessfulEmbeddedLoadEnds++;
        }
        else
        {
            FailedEmbeddedLoadEnds++;
        }
    }

    public void IncrementEmbeddedLoadFailure(string reason)
    {
        _embeddedLoadFailures.Add(reason);
    }

    public void IncrementIngestException(string source)
    {
        _ingestExceptions.Add(source);
    }

    public void IncrementDecodeStart()
    {
        DecodeStarts++;
    }

    public void IncrementDecodeEnd(bool successful)
    {
        if (successful)
        {
            SuccessfulDecodeEnds++;
        }
        else
        {
            FailedDecodeEnds++;
        }
    }

    public void IncrementEntrySkipped(string member)
    {
        _skippedEntries.Add(member);
    }

    public void IncrementEntrySkippedDueToException()
    {
        _skippedEntries.Add("exception");
    }

    public void IncrementStatusReportIgnored(string status)
    {
        _ignoredStatusReports.Add(status);
    }

    public void IncrementValueIgnored(string member)
    {
        _ignoredValues.Add(member);
    }

    public void IncrementBlobRejectedDueToRollback()
    {
        BlobsRejectedDueToRollback++;
    }

    public void IncrementLookupWithoutMetadata()
    {
        LookupsWithoutMetadata++;
    }

    public void IncrementLookupWithUntrustedEntry()
    {
        LookupsWithUntrustedEntry++;
    }
}
