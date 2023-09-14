using System.Text.Json;
using NUnit.Framework;
using WebAuthn.Net.DSL;

namespace WebAuthn.Net.Models.Protocol.Attestation;

public class CredentialCreationOptionsSerializationTests
{
    [Test]
    public void CredentialCreationOptionsCanRoundtrip()
    {
        var original = JsonToVerify.Get();
        var deserialized = JsonSerializer.Deserialize<CredentialCreationOptions>(original);
        var serialized = JsonSerializer.Serialize(deserialized, new JsonSerializerOptions
        {
            WriteIndented = false
        });
        Assert.That(serialized, Is.EqualTo(original));
    }
}
