using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace WebAuthn.Net.Services.Static;

public class JwtValidatorTests
{
    [Test]
    public async Task ValidateAsync_ReturnsValid_ForRs256TokenSignedByProvidedKey()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateToken("RS256", input => rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        var result = await JwtValidator.ValidateAsync(token, new[] { PublicKey(rsa) }, CancellationToken.None);

        Assert.That(result.IsValid, Is.True, result.Exception?.ToString());
    }

    [Test]
    public async Task ValidateAsync_ReturnsValid_ForEs256TokenSignedByProvidedKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = CreateToken("ES256", input => ecdsa.SignData(input, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using var publicKey = ECDsa.Create(ecdsa.ExportParameters(false));

        var result = await JwtValidator.ValidateAsync(token, new SecurityKey[] { new ECDsaSecurityKey(publicKey) }, CancellationToken.None);

        Assert.That(result.IsValid, Is.True, result.Exception?.ToString());
    }

    // RFC 7518 §3.1: only the asymmetric algorithms are acceptable for tokens verified with public keys taken from certificates -
    // even when a caller passes a symmetric key, an HMAC token must be rejected (and the handler's internals are not relied upon for that)
    [Test]
    public async Task ValidateAsync_ReturnsInvalid_ForHs256Token_EvenWhenMatchingSymmetricKeyIsProvided()
    {
        var secret = RandomNumberGenerator.GetBytes(32);
        var token = CreateToken("HS256", input => HMACSHA256.HashData(secret, input));

        var result = await JwtValidator.ValidateAsync(token, new SecurityKey[] { new SymmetricSecurityKey(secret) }, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(result.IsValid, Is.False);
            Assert.That(result.Exception, Is.Not.Null);
        });
    }

    [Test]
    public async Task ValidateAsync_ReturnsInvalid_ForHs256Token_SignedWithPublicKeyBytes()
    {
        // the classic algorithm confusion: the RSA public key material is used as the HMAC secret
        using var rsa = RSA.Create(2048);
        var publicKeyBytes = rsa.ExportSubjectPublicKeyInfo();
        var token = CreateToken("HS256", input => HMACSHA256.HashData(publicKeyBytes, input));

        var result = await JwtValidator.ValidateAsync(token, new[] { PublicKey(rsa) }, CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task ValidateAsync_ReturnsInvalid_ForUnsignedToken()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateToken("none", static _ => Array.Empty<byte>());

        var result = await JwtValidator.ValidateAsync(token, new[] { PublicKey(rsa) }, CancellationToken.None);

        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    public async Task ValidateAsync_WithExplicitMaximumTokenSize_ReturnsInvalid_ForLargerToken_WhileTheOverloadWithoutLimitAcceptsIt()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateToken("RS256", input => rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), payloadPadding: TokenValidationParameters.DefaultMaximumTokenSizeInBytes);
        Assert.That(token, Has.Length.GreaterThan(TokenValidationParameters.DefaultMaximumTokenSizeInBytes), "precondition: the token is larger than the default limit");

        var limited = await JwtValidator.ValidateAsync(token, new[] { PublicKey(rsa) }, TokenValidationParameters.DefaultMaximumTokenSizeInBytes, CancellationToken.None);
        var unlimited = await JwtValidator.ValidateAsync(token, new[] { PublicKey(rsa) }, CancellationToken.None);

        Assert.Multiple(() =>
        {
            Assert.That(limited.IsValid, Is.False);
            Assert.That(unlimited.IsValid, Is.True, unlimited.Exception?.ToString());
        });
    }

    [Test]
    public async Task ValidateAsync_WithExplicitMaximumTokenSize_ReturnsValid_ForTokenWithinTheLimit()
    {
        using var rsa = RSA.Create(2048);
        var token = CreateToken("RS256", input => rsa.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));

        var result = await JwtValidator.ValidateAsync(token, new[] { PublicKey(rsa) }, TokenValidationParameters.DefaultMaximumTokenSizeInBytes, CancellationToken.None);

        Assert.That(result.IsValid, Is.True, result.Exception?.ToString());
    }

    private static RsaSecurityKey PublicKey(RSA rsa)
    {
        return new(rsa.ExportParameters(false));
    }

    // a JWS in compact serialization with the given 'alg' and a signature produced by 'sign' over the signing input (ASCII of header.payload)
    private static string CreateToken(string alg, Func<byte[], byte[]> sign, int payloadPadding = 0)
    {
        var header = new Dictionary<string, object> { ["alg"] = alg, ["typ"] = "JWT" };
        var payload = new Dictionary<string, object> { ["nonce"] = "AAAA", ["iat"] = 1_700_000_000 };
        if (payloadPadding > 0)
        {
            payload["padding"] = new string('p', payloadPadding);
        }

        var signingInput = $"{WebEncoders.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header))}.{WebEncoders.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload))}";
        var signature = sign(Encoding.ASCII.GetBytes(signingInput));
        return $"{signingInput}.{WebEncoders.Base64UrlEncode(signature)}";
    }
}
