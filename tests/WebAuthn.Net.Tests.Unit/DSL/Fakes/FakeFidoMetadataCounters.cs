using System.Collections.Generic;
using WebAuthn.Net.Services.Metrics;

namespace WebAuthn.Net.DSL.Fakes;

public class FakeFidoMetadataCounters : IFidoMetadataCounters
{
    private readonly List<string> _ignoredStatusReports = new();
    private readonly List<string> _ignoredValues = new();
    private readonly List<string> _skippedEntries = new();

    public int DecodeStarts { get; private set; }

    public int SuccessfulDecodeEnds { get; private set; }

    public int FailedDecodeEnds { get; private set; }

    public IReadOnlyList<string> SkippedEntries => _skippedEntries;

    public IReadOnlyList<string> IgnoredStatusReports => _ignoredStatusReports;

    public IReadOnlyList<string> IgnoredValues => _ignoredValues;

    public int BlobsRejectedDueToRollback { get; private set; }

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
}
