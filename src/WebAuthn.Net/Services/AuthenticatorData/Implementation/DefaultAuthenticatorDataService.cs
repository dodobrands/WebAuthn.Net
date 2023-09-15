using System;
using System.Buffers.Binary;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Services.AuthenticatorData.Models;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Implementation;

public class DefaultAuthenticatorDataService : IAuthenticatorDataService
{
    private const int RpIdHashSize = 32;
    private const int SignCountSize = 4;
    private const int RpIdHashOffset = 0;
    private const int FlagsOffset = 32;
    private const int SignCountOffset = 33;
    private const int EncodedDataMinLength = 37;

    public AuthenticatorDataPayload GetAuthenticatorData(byte[] encodedAuthenticatorData)
    {
        ArgumentNullException.ThrowIfNull(encodedAuthenticatorData);

        if (encodedAuthenticatorData.Length < EncodedDataMinLength)
        {
            throw new ArgumentException($"The minimum size of the encoded authenticator data structure is {EncodedDataMinLength} bytes.");
        }

        var rpIdHashBytes = encodedAuthenticatorData.AsSpan(RpIdHashOffset, RpIdHashSize).ToArray();
        var flags = ((AuthenticatorDataFlags) encodedAuthenticatorData[FlagsOffset]).FlagsToSet();
        var signCount = BinaryPrimitives.ReadUInt32BigEndian(encodedAuthenticatorData.AsSpan(SignCountOffset, SignCountSize));

        return new(rpIdHashBytes, flags, signCount);
    }
}
