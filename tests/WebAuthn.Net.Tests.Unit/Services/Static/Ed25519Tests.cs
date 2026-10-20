using System;
using System.Threading.Tasks;
using NUnit.Framework;

namespace WebAuthn.Net.Services.Static;

public class Ed25519Tests
{
    // https://www.rfc-editor.org/rfc/rfc8032#section-7.1 - TEST 1
    private const string Test1PublicKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private const string Test1Message = "";
    private const string Test1Signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    // https://www.rfc-editor.org/rfc/rfc8032#section-7.1 - TEST 2
    private const string Test2PublicKey = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    private const string Test2Message = "72";
    private const string Test2Signature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

    // https://www.rfc-editor.org/rfc/rfc8032#section-7.1 - TEST 3
    private const string Test3PublicKey = "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025";
    private const string Test3Message = "af82";
    private const string Test3Signature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";

    [Test]
    public void IsAvailable_ReturnsTrue_WhenTheNativeLibraryIsShippedForThePlatform()
    {
        Assert.That(Ed25519.IsAvailable, Is.True);
    }

    [TestCase(Test1PublicKey, Test1Message, Test1Signature)]
    [TestCase(Test2PublicKey, Test2Message, Test2Signature)]
    [TestCase(Test3PublicKey, Test3Message, Test3Signature)]
    public void Verify_ReturnsTrue_ForRfc8032TestVectors(string publicKey, string message, string signature)
    {
        var valid = Ed25519.Verify(Convert.FromHexString(publicKey), Convert.FromHexString(message), Convert.FromHexString(signature));

        Assert.That(valid, Is.True);
    }

    [Test]
    public void Verify_ReturnsFalse_WhenSignatureIsTampered()
    {
        var signature = Convert.FromHexString(Test1Signature);
        signature[0] ^= 0x01;

        var valid = Ed25519.Verify(Convert.FromHexString(Test1PublicKey), Convert.FromHexString(Test1Message), signature);

        Assert.That(valid, Is.False);
    }

    [Test]
    public void Verify_ReturnsFalse_WhenMessageDiffers()
    {
        var valid = Ed25519.Verify(Convert.FromHexString(Test2PublicKey), new byte[] { 0x73 }, Convert.FromHexString(Test2Signature));

        Assert.That(valid, Is.False);
    }

    [Test]
    public void Verify_ReturnsFalse_WhenPublicKeyIsAnother()
    {
        var valid = Ed25519.Verify(Convert.FromHexString(Test3PublicKey), Convert.FromHexString(Test2Message), Convert.FromHexString(Test2Signature));

        Assert.That(valid, Is.False);
    }

    [TestCase(0)]
    [TestCase(31)]
    [TestCase(33)]
    public void Verify_ReturnsFalse_WhenPublicKeyIsNot32BytesLong(int publicKeyLength)
    {
        var valid = Ed25519.Verify(new byte[publicKeyLength], Convert.FromHexString(Test1Message), Convert.FromHexString(Test1Signature));

        Assert.That(valid, Is.False);
    }

    [TestCase(0)]
    [TestCase(63)]
    [TestCase(65)]
    public void Verify_ReturnsFalse_WhenSignatureIsNot64BytesLong(int signatureLength)
    {
        var valid = Ed25519.Verify(Convert.FromHexString(Test1PublicKey), Convert.FromHexString(Test1Message), new byte[signatureLength]);

        Assert.That(valid, Is.False);
    }

    [Test]
    public void Verify_ReturnsTrue_WhenCalledConcurrently()
    {
        var publicKey = Convert.FromHexString(Test3PublicKey);
        var message = Convert.FromHexString(Test3Message);
        var signature = Convert.FromHexString(Test3Signature);
        var results = new bool[256];

        Parallel.For(0, results.Length, i => results[i] = Ed25519.Verify(publicKey, message, signature));

        Assert.That(results, Is.All.True);
    }
}
