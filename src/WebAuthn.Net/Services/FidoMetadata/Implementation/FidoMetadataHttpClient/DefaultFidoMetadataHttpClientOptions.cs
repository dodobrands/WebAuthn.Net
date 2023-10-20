using System;
using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataHttpClient;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class DefaultFidoMetadataHttpClientOptions
{
    public Uri Mds3BlobUri { get; set; } = new("https://mds3.fidoalliance.org", UriKind.Absolute);
}
