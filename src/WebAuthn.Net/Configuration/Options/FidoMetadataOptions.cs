using System;

namespace WebAuthn.Net.Configuration.Options;

public class FidoMetadataOptions
{
    public Uri Mds3BlobUri { get; set; } = new("https://mds3.fidoalliance.org", UriKind.Absolute);
}
