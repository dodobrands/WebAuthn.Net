using System.Text.Json;
using NUnit.Framework;
using WebAuthn.Net.Models.Protocol.Creation;
using WebAuthn.Net.Models.Protocol.Enums;

namespace WebAuthn.Net.Models.Protocol.Request;

public class CredentialCreationOptionsSerializationTests
{
    [Test]
    public void CanSerialize()
    {
        var expectedJson = @"{
  ""publicKey"": {
    ""rp"": {
      ""id"": ""RpEntity_Id"",
      ""name"": ""RpEntity_Name""
    },
    ""user"": {
      ""id"": ""AQ=="",
      ""displayName"": ""PublicKeyCredentialUserEntity_DisplayName"",
      ""name"": ""PublicKeyCredentialUserEntity_Name""
    },
    ""challenge"": ""Ag=="",
    ""pubKeyCredParams"": [
      {
        ""type"": ""public-key"",
        ""alg"": -7
      }
    ],
    ""timeout"": 3,
    ""excludeCredentials"": [
      {
        ""type"": ""public-key"",
        ""id"": ""BA=="",
        ""transports"": [
          ""ble""
        ]
      }
    ],
    ""authenticatorSelection"": {
      ""authenticatorAttachment"": ""cross-platform"",
      ""residentKey"": ""required"",
      ""requireResidentKey"": true,
      ""userVerification"": ""preferred""
    },
    ""attestation"": ""direct""
  }
}";
        var expectedObject = new CredentialCreationOptions(
            new(new("RpEntity_Id", "RpEntity_Name"),
            new(new byte[] { 1 }, "PublicKeyCredentialUserEntity_DisplayName", "PublicKeyCredentialUserEntity_Name"),
            new byte[] { 2 },
            new PublicKeyCredentialParameters[] { new(PublicKeyCredentialType.PublicKey, COSEAlgorithmIdentifier.ES256) }, 3,
            new PublicKeyCredentialDescriptor[] { new(PublicKeyCredentialType.PublicKey, new byte[] { 4 }, new[] { AuthenticatorTransport.Ble }) },
            new(AuthenticatorAttachment.CrossPlatform, ResidentKeyRequirement.Required, true, UserVerificationRequirement.Preferred), AttestationConveyancePreference.Direct, null));

        var serialized = JsonSerializer.Serialize(expectedObject, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        TestContext.WriteLine(serialized);

        Assert.That(serialized, Is.EqualTo(expectedJson));

        //var deserialized = JsonSerializer.Deserialize<CredentialCreationOptions>(serialized);
    }
}
