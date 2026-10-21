using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using WebAuthn.Net.DSL.Fakes;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Serialization.Json.Implementation;
using static WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AttestationStatementVerifierTestHelpers;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet;

// Tests of DefaultAndroidSafetyNetAttestationStatementVerifier.VerifyAsync: every attestation is built from scratch (a self-signed "attest.android.com" certificate signs a SafetyNet-like JWS),
// valid in every respect except the one rule a test breaks. The verifier does not validate the chain (that is the trust path validator's job), so the self-signed certificate stands in for Google's.
public class DefaultAndroidSafetyNetAttestationStatementVerifierTests
{
    // ---------------------------------------------------------------------------------------------
    // Positive

    [Test]
    public async Task VerifyAsync_Succeeds_ForWellFormedJws()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create();

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.Fmt, Is.EqualTo(AttestationStatementFormat.AndroidSafetyNet));
            Assert.That(result.Ok.AttestationType, Is.EqualTo(AttestationType.Basic));
            Assert.That(result.Ok.AttestationTrustPath, Is.EqualTo(new[] { attestation.Certificate.RawData }));
            Assert.That(result.Ok.AttestationRootCertificates, Is.EquivalentTo(AndroidSafetyNetRoots.Certificates));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Step 2: 'response' is client-supplied and must never throw

    [TestCase("this.is.not-a-valid-jws")]
    [TestCase("")]
    [TestCase("a")]
    [TestCase("a.b")]
    [TestCase("not base64url!.eyJhIjoxfQ.c2ln")]
    [TestCase("eyJhbGciOiJSUzI1NiJ9.bm90IGpzb24.c2ln")] // header ok, payload is not JSON
    public async Task VerifyAsync_Fails_WithoutException_WhenResponseIsNotJws(string response)
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create();
        var malformed = new AndroidSafetyNetAttestationStatement("1", Encoding.UTF8.GetBytes(response));

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation with { AttStmt = malformed }));

        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            AssertWarning(verifier, "'response' of the Android SafetyNet attestation statement is not a JWS in compact serialization");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenResponseIsNotUtf8()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create();
        var malformed = new AndroidSafetyNetAttestationStatement("1", new byte[] { 0xFF, 0xFE, 0x2E, 0xC0, 0x2E, 0x80 });

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation with { AttStmt = malformed }));

        Assert.That(result!.HasError, Is.True);
    }

    [Test]
    public async Task VerifyAsync_Fails_BeforeParsing_WhenResponseIsLargerThanDefaultMaximumTokenSize()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(payloadPadding: TokenValidationParameters.DefaultMaximumTokenSizeInBytes);
        Assert.That(attestation.AttStmt.Response, Has.Length.GreaterThan(TokenValidationParameters.DefaultMaximumTokenSizeInBytes), "precondition: the JWS is larger than the limit");

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, $"exceeds the maximum accepted JWS size of {TokenValidationParameters.DefaultMaximumTokenSizeInBytes} byte(s)");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // 'timestampMs' is client-supplied: an out-of-range value must fail, not throw

    [TestCase(long.MaxValue)]
    [TestCase(253_402_300_800_000L)] // 10000-01-01T00:00:00Z
    [TestCase(-1L)]
    [TestCase(long.MinValue)]
    public void TryGetRequiredClaims_ReturnsFalse_WithoutException_WhenTimestampMsIsOutOfRange(long timestampMs)
    {
        var verifier = new TestSafetyNetVerifier();
        var jwt = new JwtSecurityToken(claims: new[]
        {
            new Claim("nonce", "AAAA"),
            new Claim("ctsProfileMatch", "true", ClaimValueTypes.Boolean),
            new Claim("timestampMs", timestampMs.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)
        });

        var extracted = true;
        Assert.DoesNotThrow(() => extracted = verifier.GetRequiredClaims(jwt, out _, out _, out _));

        Assert.Multiple(() =>
        {
            Assert.That(extracted, Is.False);
            AssertWarning(verifier, $"'timestampMs' claim of the Android SafetyNet attestation statement is out of range: {timestampMs}");
        });
    }

    [Test]
    public void TryGetRequiredClaims_ReturnsClaims_WhenTimestampMsIsInRange()
    {
        var verifier = new TestSafetyNetVerifier();
        var timestamp = Now.AddSeconds(-5);
        var jwt = new JwtSecurityToken(claims: new[]
        {
            new Claim("nonce", "AAAA"),
            new Claim("ctsProfileMatch", "true", ClaimValueTypes.Boolean),
            new Claim("timestampMs", timestamp.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64)
        });

        var extracted = verifier.GetRequiredClaims(jwt, out var nonce, out var ctsProfileMatch, out var parsedTimestamp);

        Assert.Multiple(() =>
        {
            Assert.That(extracted, Is.True);
            Assert.That(nonce, Is.EqualTo("AAAA"));
            Assert.That(ctsProfileMatch, Is.True);
            Assert.That(parsedTimestamp, Is.EqualTo(timestamp));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WithoutException_WhenTimestampMsIsOutOfRange()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(timestampMs: long.MaxValue);

        Result<VerifiedAttestationStatement>? result = null;
        await Assert.DoesNotThrowAsync(async () => result = await verifier.VerifyAsync(attestation));

        Assert.Multiple(() =>
        {
            Assert.That(result!.HasError, Is.True);
            AssertWarning(verifier, "is out of range");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // 'x5c' of the JWS header

    [Test]
    public async Task VerifyAsync_Fails_WhenJwsHeaderX5CHasMoreThanSixteenCertificates()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(x5CRepetitions: 17);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "contains 17 certificates, which exceeds the maximum of 16");
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenJwsHeaderX5CHasSixteenCertificates()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(x5CRepetitions: 16);

        var result = await verifier.VerifyAsync(attestation);

        Assert.That(result.HasError, Is.False);
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenJwsHeaderHasNoX5C()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(x5CRepetitions: 0);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "does not contain the 'x5c' parameter");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // JWS algorithm: only the asymmetric algorithms are acceptable

    [Test]
    public async Task VerifyAsync_Fails_WhenJwsIsSignedWithHmac()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(hmacInsteadOfRsa: true);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "JWS of the Android SafetyNet attestation statement failed validation");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenJwsSignatureIsInvalid()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(corruptSignature: true);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "JWS of the Android SafetyNet attestation statement failed validation");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // JWS signing key: only the leaf certificate (the first in 'x5c') is checked to be issued to "attest.android.com" and only its chain is validated,
    // so the JWS must be signed with the key of the leaf certificate (RFC 7515 4.1.6), not with the key of a certificate that follows it

    [Test]
    public async Task VerifyAsync_Fails_WhenJwsIsSignedWithKeyOfCertificateThatFollowsLeafInX5C()
    {
        var verifier = new TestSafetyNetVerifier();
        // the leaf issued to "attest.android.com" is followed by the attacker's own certificate, whose key signed the JWS
        var attestation = SafetyNetAttestation.Create(signWithAppendedCertificate: true);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "JWS of the Android SafetyNet attestation statement failed validation");
        });
    }

    [Test]
    public async Task VerifyAsync_Succeeds_WhenJwsIsSignedWithKeyOfLeafAndX5CContainsFurtherCertificates()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(appendCertificate: true);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.False);
            Assert.That(result.Ok!.AttestationTrustPath, Has.Length.EqualTo(2));
            Assert.That(result.Ok.AttestationTrustPath?[0], Is.EqualTo(attestation.Certificate.RawData));
            Assert.That(verifier.FakeLogger.Entries, Is.Empty);
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Steps 3-4

    [Test]
    public async Task VerifyAsync_Fails_WhenNonceDoesNotMatch()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(wrongNonce: true);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'nonce' claim of the Android SafetyNet attestation statement is not equal to SHA-256");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenCtsProfileMatchIsFalse()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(ctsProfileMatch: false);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "'ctsProfileMatch' claim of the Android SafetyNet attestation statement is false");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenLeafCertificateIsNotIssuedToAttestAndroidCom()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(hostname: "attest.example.com");

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "was not issued to the hostname \"attest.android.com\"");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenTimestampIsOlderThanSixtySeconds()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(timestampMs: Now.AddSeconds(-61).ToUnixTimeMilliseconds());

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is more than 60 seconds old");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenTimestampIsInTheFuture()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(timestampMs: Now.AddSeconds(5).ToUnixTimeMilliseconds());

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "is in the future");
        });
    }

    [Test]
    public async Task VerifyAsync_Fails_WhenRequiredClaimIsMissing()
    {
        var verifier = new TestSafetyNetVerifier();
        var attestation = SafetyNetAttestation.Create(omitCtsProfileMatch: true);

        var result = await verifier.VerifyAsync(attestation);

        Assert.Multiple(() =>
        {
            Assert.That(result.HasError, Is.True);
            AssertWarning(verifier, "lacks a required claim (nonce present: True, ctsProfileMatch present: False, timestampMs present: True)");
        });
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers

    private static void AssertWarning(TestSafetyNetVerifier verifier, string messagePart)
    {
        Assert.That(
            verifier.FakeLogger.Entries.Where(static x => x.Level == LogLevel.Warning).Select(static x => x.Message),
            Has.Some.Contains(messagePart),
            $"expected a Warning containing '{messagePart}'");
    }

    private sealed record SafetyNetAttestation(AndroidSafetyNetAttestationStatement AttStmt, AttestedAuthenticatorData AuthenticatorData, byte[] ClientDataHash, X509Certificate2 Certificate)
    {
        // a SafetyNet-like JWS: header { alg: RS256, x5c: [leaf] }, payload { nonce, timestampMs, ctsProfileMatch, ... }, signed with the leaf's RSA key
        // (appendCertificate adds a second certificate after the leaf, signWithAppendedCertificate also signs the JWS with its key instead of the leaf's)
        public static SafetyNetAttestation Create(
            string hostname = "attest.android.com",
            long? timestampMs = null,
            bool ctsProfileMatch = true,
            bool omitCtsProfileMatch = false,
            bool wrongNonce = false,
            int x5CRepetitions = 1,
            bool hmacInsteadOfRsa = false,
            bool corruptSignature = false,
            int payloadPadding = 0,
            bool appendCertificate = false,
            bool signWithAppendedCertificate = false)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest($"CN={hostname}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(hostname);
            request.CertificateExtensions.Add(sanBuilder.Build());
            request.CertificateExtensions.Add(EndEntityBasicConstraints());
            var certificate = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
            using var appendedRsa = appendCertificate || signWithAppendedCertificate ? RSA.Create(2048) : null;
            using var appendedCertificate = appendedRsa is not null
                ? new CertificateRequest("CN=Appended Certificate", appendedRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30))
                : null;

            using var credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var authenticatorData = CreateAuthenticatorData(Aaguid, ToCoseEc2Key(credentialKey));
            var clientDataHash = CreateClientDataHash();
            var nonce = SHA256.HashData(Concat(authenticatorData.Raw, clientDataHash));
            if (wrongNonce)
            {
                nonce[0] ^= 0xFF;
            }

            var header = new Dictionary<string, object> { ["alg"] = hmacInsteadOfRsa ? "HS256" : "RS256" };
            if (x5CRepetitions > 0)
            {
                var x5C = Enumerable.Repeat(Convert.ToBase64String(certificate.RawData), x5CRepetitions);
                if (appendedCertificate is not null)
                {
                    x5C = x5C.Append(Convert.ToBase64String(appendedCertificate.RawData));
                }

                header["x5c"] = x5C.ToArray();
            }

            var payload = new Dictionary<string, object>
            {
                ["nonce"] = Convert.ToBase64String(nonce),
                ["timestampMs"] = timestampMs ?? Now.AddSeconds(-1).ToUnixTimeMilliseconds(),
                ["apkPackageName"] = "com.example.app",
                ["basicIntegrity"] = true,
                ["evaluationType"] = "BASIC"
            };
            if (!omitCtsProfileMatch)
            {
                payload["ctsProfileMatch"] = ctsProfileMatch;
            }

            if (payloadPadding > 0)
            {
                payload["padding"] = new string('p', payloadPadding);
            }

            var signingInput = $"{WebEncoders.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header))}.{WebEncoders.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload))}";
            var signingKey = signWithAppendedCertificate && appendedRsa is not null ? appendedRsa : rsa;
            var signature = hmacInsteadOfRsa
                ? HMACSHA256.HashData(certificate.PublicKey.EncodedKeyValue.RawData, Encoding.ASCII.GetBytes(signingInput))
                : signingKey.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            if (corruptSignature)
            {
                signature[^1] ^= 0x01;
            }

            var jws = $"{signingInput}.{WebEncoders.Base64UrlEncode(signature)}";
            return new(new("1", Encoding.UTF8.GetBytes(jws)), authenticatorData, clientDataHash, certificate);
        }
    }

    private sealed class TestSafetyNetVerifier : DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>
    {
        public TestSafetyNetVerifier() : this(new FakeLogger<DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>>())
        {
        }

        private TestSafetyNetVerifier(FakeLogger<DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>> logger)
            : base(
                new FakeTimeProvider(Now),
                new DefaultSafeJsonSerializer(NullLogger<DefaultSafeJsonSerializer>.Instance),
                new RecordingFidoMetadataSearchService(),
                logger)
        {
            FakeLogger = logger;
        }

        public FakeLogger<DefaultAndroidSafetyNetAttestationStatementVerifier<FakeWebAuthnContext>> FakeLogger { get; }

        public async Task<Result<VerifiedAttestationStatement>> VerifyAsync(SafetyNetAttestation attestation)
        {
            await using var context = CreateContext();
            return await VerifyAsync(context, attestation.AttStmt, attestation.AuthenticatorData, attestation.ClientDataHash, CancellationToken.None);
        }

        public bool GetRequiredClaims(JwtSecurityToken jwt, out string? nonce, out bool? ctsProfileMatch, out DateTimeOffset? timestamp)
        {
            return TryGetRequiredClaims(jwt, out nonce, out ctsProfileMatch, out timestamp);
        }
    }
}
