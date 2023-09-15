namespace WebAuthn.Net.Services.AuthenticatorData;

public interface IAuthenticatorDataService
{
    void GetAuthenticatorData(byte[] encodedAuthenticatorData);
}
