namespace WebAuthn.Net.Sample.Mvc.Constants;

#pragma warning disable CA1034
public static class ExampleConstants
{
    public static class Host
    {
        public const string WebAuthnDisplayName = "WebAuthn.Net MVC example";
    }

    public static class CookieAuthentication
    {
        public const string AuthCookieName = "WebauthnExampleUser";

        public const string RegistrationSessionId = "WebauthnRegId";
        public const string AuthAssertionSessionId = "WebauthnAssertId";
    }
}
#pragma warning restore CA1034
