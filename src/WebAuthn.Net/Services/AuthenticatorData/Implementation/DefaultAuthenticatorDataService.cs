using System;
using System.Buffers.Binary;
using WebAuthn.Net.Extensions;
using WebAuthn.Net.Services.AuthenticatorData.Models;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Implementation;

/// <summary>
///     Default implementation of the service for working with the <a href="https://www.w3.org/TR/webauthn-3/#authenticator-data">authenticator data</a> structure.
/// </summary>
public class DefaultAuthenticatorDataService : IAuthenticatorDataService
{
    // https://www.w3.org/TR/webauthn-3/#table-authData

    // Sizes
    private const int RpIdHashSize = 32;
    private const int SignCountSize = 4;

    // Offsets
    private const int RpIdHashOffset = 0;
    private const int FlagsOffset = 32;
    private const int SignCountOffset = 33;

    // Size of the entire data structure.
    private const int EncodedDataMinLength = 37;

    /// <inheritdoc />
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
