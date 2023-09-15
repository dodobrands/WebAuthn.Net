using System;
using System.Collections.Generic;
using System.Linq;
using WebAuthn.Net.Services.AuthenticatorData.Models;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Implementation;

public class DefaultAuthenticatorDataService : IAuthenticatorDataService
{
    private const int RpIdHashLength = 32;
    private const int MinimalValidLength = 37;

    public AuthenticatorDataPayload GetAuthenticatorData(byte[] encodedAuthenticatorData)
    {
        if (encodedAuthenticatorData is null || encodedAuthenticatorData.Length < MinimalValidLength)
        {
            //TODO: custom exception
            throw new ArgumentException("Array too short");
        }

        var rpIdHashBytes = encodedAuthenticatorData.Take(RpIdHashLength).ToArray();

        return new AuthenticatorDataPayload(rpIdHashBytes, new HashSet<AuthenticatorDataFlags>(0));
        //BinaryPrimitives.ReadUInt32BigEndian(bytes)
    }
}
