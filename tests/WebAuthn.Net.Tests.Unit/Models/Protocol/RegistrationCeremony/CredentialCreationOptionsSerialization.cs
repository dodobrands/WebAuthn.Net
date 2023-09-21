using System.Text.Json;
using NUnit.Framework;
using WebAuthn.Net.DSL;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.RegistrationCeremony;

public class CredentialCreationOptionsSerializationTests
{
    [Test]
    public void SerializeExample()
    {
        var expected = new CredentialCreationOptions(
            new(
                new("PublicKeyCredentialRpEntity_Id", "PublicKeyCredentialRpEntity_Name"),
                new(new byte[] { 1 }, "PublicKeyCredentialUserEntity_DisplayName", "PublicKeyCredentialUserEntity_Name"),
                new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5 },
                new PublicKeyCredentialParameters[] { new(PublicKeyCredentialType.PublicKey, CoseAlgorithmIdentifier.Es256) },
                3,
                new PublicKeyCredentialDescriptor[] { new(PublicKeyCredentialType.PublicKey, new byte[] { 4 }, new[] { AuthenticatorTransport.Ble }) },
                new(AuthenticatorAttachment.Platform, ResidentKeyRequirement.Preferred, true, UserVerificationRequirement.Required),
                AttestationConveyancePreference.Enterprise, new()
            )
        );
        TestContext.WriteLine(JsonSerializer.Serialize(expected));
    }

    [Test]
    public void CanRoundtrip()
    {
        var expected = CredentialCreationOptionsExample1();
        var deserialized = JsonSerializer.Deserialize<CredentialCreationOptions>(expected);
        var reSerialized = JsonSerializer.Serialize(deserialized);
        Assert.That(reSerialized, Is.EqualTo(expected));
    }

    private string CredentialCreationOptionsExample1()
    {
        return this.GetResourceByMethodName();
    }
}
