using System.Linq;
using NUnit.Framework;
using WebAuthn.Net.Services.AuthenticatorData.Models.Enums;

namespace WebAuthn.Net.Services.AuthenticatorData.Implementation;

public class DefaultAuthenticatorDataServiceTests
{
    private const int RpIdHashLength = 32;
    private const int MinimalValidLength = 37;

    private readonly IAuthenticatorDataService _authenticatorDataService = new DefaultAuthenticatorDataService();

    [TestCase(MinimalValidLength)]
    [TestCase(MinimalValidLength * 2)]
    public void GetAuthenticatorData_ReturnsCorrectRpIdHash_WhenHasValidArray(int arrayToParseLength)
    {
        var bytesToParse = CreateArrayWithFixedLength(arrayToParseLength);

        var parsedData = _authenticatorDataService.GetAuthenticatorData(bytesToParse);

        Assert.That(bytesToParse.Take(RpIdHashLength).ToArray(), Is.EqualTo(parsedData.RpIdHash));
    }

    public void GetAuthenticatorData_ReturnsCorrectFlags_WhenHasValidArray()
    {
        var validRpIdHash = CreateArrayWithFixedLength(RpIdHashLength);

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

    private static byte CreateValidFlagsByte(AuthenticatorDataFlags flags)
    {

    }
}
