using WebAuthn.Net.Services.AuthenticatorData.Models;

namespace WebAuthn.Net.Services.AuthenticatorData;

public interface IAuthenticatorDataService
{
    AuthenticatorDataPayload GetAuthenticatorData(byte[] encodedAuthenticatorData);
}
