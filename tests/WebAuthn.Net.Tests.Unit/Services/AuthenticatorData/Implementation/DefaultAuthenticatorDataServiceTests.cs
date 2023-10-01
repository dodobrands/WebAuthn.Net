using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using WebAuthn.Net.Services.Cryptography.Cose.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Implementation;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Implementation;

namespace WebAuthn.Net.Services.AuthenticatorData.Implementation;

public class DefaultAuthenticatorDataServiceTests
{
    private const int RpIdHashSize = 32;
    private const int FlagsOffset = 32;
    private const int EncodedDataMinLength = 37;

    private readonly IAuthenticatorDataDecoder _authenticatorDataDecoder =
        new DefaultAuthenticatorDataDecoder(
            new DefaultCoseKeyDecoder(
                new DefaultCborDecoder(NullLogger<DefaultCborDecoder>.Instance),
                NullLogger<DefaultCoseKeyDecoder>.Instance),
            NullLogger<DefaultAuthenticatorDataDecoder>.Instance);

    [TestCase(EncodedDataMinLength)]
    [TestCase(EncodedDataMinLength * 2)]
    public void GetAuthenticatorData_ReturnsCorrectRpIdHash_WhenHasValidArray(int arrayToParseLength)
    {
        var bytesToParse = CreateArrayWithFixedLength(arrayToParseLength);

        var parsedData = _authenticatorDataDecoder.Decode(bytesToParse);

        Assert.That(parsedData.HasError, Is.EqualTo(false));
        Assert.That(parsedData.Ok!.RpIdHash, Is.EqualTo(bytesToParse.Take(RpIdHashSize).ToArray()));
    }

    [Test]
    public void GetAuthenticatorData_ParsesFlags_WhenHasValidFlags()
    {
        var flagsToEncode = new List<AuthenticatorDataFlags>
        {
            AuthenticatorDataFlags.UserPresent,
            AuthenticatorDataFlags.UserVerified
        };
        var arrayToParse = CreateValidArrayWithFlags(flagsToEncode);

        var parsedData = _authenticatorDataDecoder.Decode(arrayToParse);

        Assert.That(parsedData.HasError, Is.EqualTo(false));
        Assert.That(parsedData.Ok!.Flags, Is.EquivalentTo(flagsToEncode));
    }

    private static byte[] CreateArrayWithFixedLength(int length)
    {
        var array = new byte[length];
        for (var i = 0; i < length; i++)
        {
            array[i] = 0x20;
        }

        return array;
    }

    private static byte[] CreateValidArrayWithFlags(IEnumerable<AuthenticatorDataFlags> flagsToInclude)
    {
        var array = new byte[EncodedDataMinLength];
        AuthenticatorDataFlags flags = default;
        foreach (var flag in flagsToInclude)
        {
            flags |= flag;
        }

        array[FlagsOffset] = (byte) flags;
        return array;
    }
}
