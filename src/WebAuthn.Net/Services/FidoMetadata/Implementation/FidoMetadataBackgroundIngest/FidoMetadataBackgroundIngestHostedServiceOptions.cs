using System;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataBackgroundIngest;

public class FidoMetadataBackgroundIngestHostedServiceOptions
{
    public TimeSpan IngestInterval { get; set; } = TimeSpan.FromDays(1);

    public bool ThrowExceptionOnFailure { get; set; }
}
