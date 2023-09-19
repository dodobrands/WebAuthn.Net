using System.Text.Json;
using NUnit.Framework;
using WebAuthn.Net.DSL;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.AuthenticationCeremony;

public class CredentialRequestOptionsSerializationTests
{
    [Test]
    public void SerializeExample()
    {
        var expected = new CredentialRequestOptions(
            CredentialMediationRequirement.Required,
            new(
                new byte[]{1},
                2, "AA-AA_",
                new[]
                {
                    new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PublicKey,
                        new byte[]{3, 4},
                        new[]
                        {
                            AuthenticatorTransport.Ble,
                            AuthenticatorTransport.Internal
                        }),
                }, UserVerificationRequirement.Preferred, new()));
        TestContext.WriteLine(JsonSerializer.Serialize(expected));
    }

    [Test]
    public void CanRoundtrip()
    {
        var expected = CredentialRequestOptionsExample1();
        var deserialized = JsonSerializer.Deserialize<CredentialRequestOptions>(expected);
        var reSerialized = JsonSerializer.Serialize(deserialized);
        Assert.That(reSerialized, Is.EqualTo(expected));
    }

    private string CredentialRequestOptionsExample1() => this.GetResourceByMethodName();
}
