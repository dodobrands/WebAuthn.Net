using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Storage.AuthenticationCeremony.Models;

public class AuthenticationCeremonyRpParameters
{
    public AuthenticationCeremonyRpParameters(string rpId, string[] origins, bool allowIframe, string[]? topOrigins)
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
