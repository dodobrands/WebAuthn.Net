using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.TimeProvider;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationStatementVerifier.Implementation.AndroidSafetyNet;

public class DefaultAndroidSafetyNetAttestationStatementVerifier : IAndroidSafetyNetAttestationStatementVerifier
{
    private readonly ITimeProvider _timeProvider;

    public DefaultAndroidSafetyNetAttestationStatementVerifier(ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        _timeProvider = timeProvider;
    }

    [SuppressMessage("Security", "CA5404:Do not disable token validation checks")]
    public Result<AttestationStatementVerificationResult> Verify(
        AndroidSafetyNetAttestationStatement attStmt,
        AttestationStatementVerificationAuthData authData,
        byte[] clientDataHash)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1) Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Verify that response is a valid SafetyNet response of version ver by following the steps indicated by the SafetyNet online documentation.
        // As of this writing, there is only one format of the SafetyNet response and ver is reserved for future use.
        var jwtString = Encoding.UTF8.GetString(attStmt.Response);
        var jwt = new JwtSecurityToken(jwtString);
        if (!TryGetCertificates(jwt, out var certificates))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!TryGetSecurityKeys(certificates, out var securityKeys))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = securityKeys,
            ValidateLifetime = false,
            ValidateAudience = false,
            ValidateIssuer = false
        };
        var tokenHandler = new JwtSecurityTokenHandler();
        tokenHandler.InboundClaimFilter.Clear();
        tokenHandler.InboundClaimTypeMap.Clear();
        tokenHandler.OutboundAlgorithmMap.Clear();
        tokenHandler.OutboundClaimTypeMap.Clear();
        tokenHandler.ValidateToken(jwtString, validationParameters, out var validatedToken);
        if (validatedToken is not JwtSecurityToken validatedJwt)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!TryGetRequiredClaims(validatedJwt, out var nonce, out var ctsProfileMatch, out var timestamp))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) Verify that the nonce attribute in the payload of response is identical to the
        // Base64 encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.
        var dataToVerify = SHA256.HashData(Concat(authData.RawAuthData, clientDataHash));
        var binaryNonce = Convert.FromBase64String(nonce);
        if (!binaryNonce.AsSpan().SequenceEqual(dataToVerify.AsSpan()))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 4) Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the SafetyNet online documentation.
        if (ctsProfileMatch.Value != true)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        var attestationCert = certificates.First();
        if (attestationCert.GetNameInfo(X509NameType.DnsName, false) is not "attest.android.com")
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        var currentDate = _timeProvider.GetPreciseUtcDateTime();
        if (currentDate < timestamp.Value)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (currentDate.Subtract(timestamp.Value) > TimeSpan.FromSeconds(60))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 5) If successful, return implementation-specific values representing attestation type Basic and attestation trust path x5c.
        var result = new AttestationStatementVerificationResult(AttestationType.Basic, certificates);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    private bool TryGetCertificates(JwtSecurityToken jwt, [NotNullWhen(true)] out X509Certificate2[]? certificates)
    {
        if (!jwt.Header.TryGetValue("x5c", out var certificatesObject) || certificatesObject is null)
        {
            certificates = null;
            return false;
        }

        if (certificatesObject is string certificatesString)
        {
            var rawCert = WebEncoders.Base64UrlDecode(certificatesString);
            var resultCert = new X509Certificate2(rawCert);
            certificates = new[] { resultCert };
            return true;
        }

        if (certificatesObject is IEnumerable certificatesEnumerable)
        {
            var result = new List<X509Certificate2>();
            foreach (var certificateObject in certificatesEnumerable)
            {
                if (certificateObject is not string certificateString)
                {
                    certificates = null;
                    return false;
                }

                var rawCert = WebEncoders.Base64UrlDecode(certificateString);
                var resultCert = new X509Certificate2(rawCert);
                var currentDate = _timeProvider.GetPreciseUtcDateTime();
                if (currentDate < resultCert.NotBefore || currentDate > resultCert.NotAfter)
                {
                    certificates = null;
                    return false;
                }

                result.Add(resultCert);
            }

            if (result.Count == 0)
            {
                certificates = null;
                return false;
            }

            certificates = result.ToArray();
            return true;
        }

        certificates = null;
        return false;
    }

    private static bool TryGetSecurityKeys(X509Certificate2[] certificates, [NotNullWhen(true)] out SecurityKey[]? securityKeys)
    {
        var result = new SecurityKey[certificates.Length];
        for (var i = 0; i < certificates.Length; i++)
        {
            var currentCertificate = certificates[i];
            if (currentCertificate.GetECDsaPublicKey() is { } ecdsaPublicKey)
            {
                result[i] = new ECDsaSecurityKey(ecdsaPublicKey);
            }
            else if (currentCertificate.GetRSAPublicKey() is { } rsaPublicKey)
            {
                result[i] = new RsaSecurityKey(rsaPublicKey);
            }
            else
            {
                securityKeys = null;
                return false;
            }
        }

        securityKeys = result;
        return true;
    }

    private static bool TryGetRequiredClaims(
        JwtSecurityToken validatedJwt,
        [NotNullWhen(true)] out string? nonce,
        [NotNullWhen(true)] out bool? ctsProfileMatch,
        [NotNullWhen(true)] out DateTimeOffset? timestamp)
    {
        string? resultNonce = null;
        bool? resultCtsProfileMatch = null;
        DateTimeOffset? resultTimestamp = null;

        foreach (var claim in validatedJwt.Claims)
        {
            if (claim is { Type: "nonce", Value.Length: > 0 })
            {
                resultNonce = claim.Value;
            }
            else if (claim is { Type: "ctsProfileMatch", Value.Length: > 0 } && bool.TryParse(claim.Value, out var parsedCtsProfileMatch))
            {
                resultCtsProfileMatch = parsedCtsProfileMatch;
            }
            else if (claim is { Type: "timestampMs", Value.Length: > 0 } && long.TryParse(claim.Value, out var parsedTimestampMs))
            {
                resultTimestamp = DateTimeOffset.UnixEpoch.AddMilliseconds(parsedTimestampMs);
            }
        }

        if (!string.IsNullOrEmpty(resultNonce)
            && resultCtsProfileMatch.HasValue
            && resultTimestamp.HasValue)
        {
            nonce = resultNonce;
            ctsProfileMatch = resultCtsProfileMatch.Value;
            timestamp = resultTimestamp.Value;
            return true;
        }

        nonce = null;
        ctsProfileMatch = null;
        timestamp = null;
        return false;
    }
}
