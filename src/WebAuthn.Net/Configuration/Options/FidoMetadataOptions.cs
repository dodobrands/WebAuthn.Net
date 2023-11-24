using System;

namespace WebAuthn.Net.Configuration.Options;

/// <summary>
///     Options that define behavior when working with FIDO Metadata Service.
/// </summary>
public class FidoMetadataOptions
{
    /// <summary>
    ///     The address from where to download the FIDO Metadata Service metadata blob in the 3rd version format.
    /// </summary>
    public Uri Mds3BlobUri { get; set; } = new("https://mds3.fidoalliance.org", UriKind.Absolute);
}
