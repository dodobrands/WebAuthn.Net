using System;
using WebAuthn.Net.Services.AuthenticatorData.Models;

namespace WebAuthn.Net.Services.AuthenticatorData.Implementation;

public class DefaultAuthenticatorDataService : IAuthenticatorDataService
{
    public AuthenticatorDataPayload GetAuthenticatorData(byte[] encodedAuthenticatorData)
    {
        throw new NotImplementedException();
    }
}
