using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Implementation;

public class DefaultAuthenticatorDataServiceTests
{
    private const int RpIdHashSize = 32;
    private const int FlagsOffset = 32;
    private const int EncodedDataMinLength = 37;

    private readonly IAuthenticatorDataService _authenticatorDataService = new DefaultAuthenticatorDataService();

    [TestCase(EncodedDataMinLength)]
    [TestCase(EncodedDataMinLength * 2)]
    public void GetAuthenticatorData_ReturnsCorrectRpIdHash_WhenHasValidArray(int arrayToParseLength)
    {
        var bytesToParse = CreateArrayWithFixedLength(arrayToParseLength);

        var parsedData = _authenticatorDataService.GetAuthenticatorData(bytesToParse);

        Assert.That(bytesToParse.Take(RpIdHashSize).ToArray(), Is.EqualTo(parsedData.RpIdHash));
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

        var parsedData = _authenticatorDataService.GetAuthenticatorData(arrayToParse);

        Assert.That(parsedData.Flags, Is.EquivalentTo(flagsToEncode));
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
