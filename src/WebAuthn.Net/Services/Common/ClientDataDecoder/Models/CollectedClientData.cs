namespace WebAuthn.Net.Services.Common.ClientDataDecoder.Models;

public class CollectedClientData
{
    public CollectedClientData(
        string type,
        string challenge,
        string origin,
        string? topOrigin,
        bool? crossOrigin,
        TokenBinding? tokenBinding)
    {
        Type = type;
        Challenge = challenge;
        Origin = origin;
        TopOrigin = topOrigin;
        CrossOrigin = crossOrigin;
        TokenBinding = tokenBinding;
    }

    public string Type { get; }

    public string Challenge { get; }

    public string Origin { get; }

    public string? TopOrigin { get; }

    public bool? CrossOrigin { get; }

    public TokenBinding? TokenBinding { get; }
}
