using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Storage.Models;

public class ExpectedRpParameters
{
    public ExpectedRpParameters(string rpId, string[] origins, bool allowIframe, string[]? topOrigins)
    {
        RpId = rpId;
        Origins = origins;
        AllowIframe = allowIframe;
        TopOrigins = topOrigins;
    }

    public string RpId { get; }

    public string[] Origins { get; }

    [MemberNotNullWhen(true, nameof(TopOrigins))]
    public bool AllowIframe { get; }

    public string[]? TopOrigins { get; }
}
