using System.Text.Json;
using NUnit.Framework;
using WebAuthn.Net.DSL;

namespace WebAuthn.Net.Models.Protocol.Attestation;

public class CredentialCreationOptionsSerializationTests
{
    [Test]
    public void CanRoundtrip()
    {
        var expected = CredentialCreationOptionsExample1();
        var deserialized = JsonSerializer.Deserialize<CredentialCreationOptions>(expected);
        var reSerialized = JsonSerializer.Serialize(deserialized);
        Assert.That(reSerialized, Is.EqualTo(expected));
    }

    private static string CredentialCreationOptionsExample1() => JsonToVerify.Get();
}
