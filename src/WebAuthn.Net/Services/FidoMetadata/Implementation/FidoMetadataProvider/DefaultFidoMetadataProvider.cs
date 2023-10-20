using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultFidoMetadataProvider : IFidoMetadataProvider
{
    public DefaultFidoMetadataProvider(IFidoMetadataHttpClient metadataHttpClient)
    {
        ArgumentNullException.ThrowIfNull(metadataHttpClient);
        MetadataHttpClient = metadataHttpClient;
    }

    protected IFidoMetadataHttpClient MetadataHttpClient { get; }

    public virtual async Task<MetadataBLOBPayloadJSON> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rawMetadata = await MetadataHttpClient.DownloadMetadataAsync(cancellationToken);
        throw new NotImplementedException();
    }
}
