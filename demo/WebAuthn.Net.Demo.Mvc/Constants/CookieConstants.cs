namespace WebAuthn.Net.Demo.Mvc.Constants;

public static class CookieConstants
{
    public const string Prefix = "webauthn";

    public const string RegistrationCeremonyId = Prefix + "regid";
    public const string AuthenticationCeremonyId = Prefix + "authid";
    public const string UserHandle = Prefix + "uh";
    public const string Credentials = Prefix + "cr";
}
