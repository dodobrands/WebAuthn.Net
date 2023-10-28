using System.Diagnostics.CodeAnalysis;

namespace WebAuthn.Net.Configuration.Options;

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public class AuthenticationCeremonyOptions
{
    public uint DefaultTimeout { get; set; } = 300_000;

    public bool AbortCeremonyWhenSignCountIsLessOrEqualStoredValue { get; set; } = true;

    public bool AllowToUpdateUserUserVerifiedFlag { get; set; }
}
