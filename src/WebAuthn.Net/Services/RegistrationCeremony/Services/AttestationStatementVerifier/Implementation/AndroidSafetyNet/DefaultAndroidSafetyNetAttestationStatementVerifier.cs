using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AuthenticatorDataDecoder.Models;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementVerifier.Implementation.AndroidSafetyNet;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAndroidSafetyNetAttestationStatementVerifier<TContext>
    : IAndroidSafetyNetAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    public DefaultAndroidSafetyNetAttestationStatementVerifier(ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        TimeProvider = timeProvider;
    }

    protected ITimeProvider TimeProvider { get; }

    [SuppressMessage("Security", "CA5404:Do not disable token validation checks")]
    public virtual async Task<Result<AttestationStatementVerificationResult>> VerifyAsync(
        TContext context,
        AndroidSafetyNetAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#sctn-android-safetynet-attestation
        // §8.5. Android SafetyNet Attestation Statement Format

        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Verify that 'response' is a valid SafetyNet response of version 'ver' by following the steps indicated by the SafetyNet online documentation.
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
        var validationResult = await tokenHandler.ValidateTokenAsync(jwtString, validationParameters);
        if (!validationResult.IsValid)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (validationResult.SecurityToken is not JwtSecurityToken validatedJwt)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (!TryGetRequiredClaims(validatedJwt, out var nonce, out var ctsProfileMatch, out var timestamp))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 3) Verify that the 'nonce' attribute in the payload of response
        // is identical to the Base64 encoding of the SHA-256 hash of the concatenation of 'authenticatorData' and 'clientDataHash'.
        var dataToVerify = SHA256.HashData(Concat(authenticatorData.Raw, clientDataHash));
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

        var currentDate = TimeProvider.GetPreciseUtcDateTime();
        if (currentDate < timestamp.Value)
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        if (currentDate.Subtract(timestamp.Value) > TimeSpan.FromSeconds(60))
        {
            return Result<AttestationStatementVerificationResult>.Fail();
        }

        // 5) If successful, return implementation-specific values representing attestation type Basic and attestation trust path x5c.
        var result = new AttestationStatementVerificationResult(AttestationStatementFormat.AndroidSafetynet, AttestationType.Basic, certificates, null);
        return Result<AttestationStatementVerificationResult>.Success(result);
    }

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetCertificates(JwtSecurityToken jwt, [NotNullWhen(true)] out X509Certificate2[]? certificates)
    {
        if (jwt is null)
        {
            certificates = null;
            return false;
        }

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
                var currentDate = TimeProvider.GetPreciseUtcDateTime();
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

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetSecurityKeys(X509Certificate2[] certificates, [NotNullWhen(true)] out SecurityKey[]? securityKeys)
    {
        if (certificates is null)
        {
            securityKeys = null;
            return false;
        }

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

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetRequiredClaims(
        JwtSecurityToken validatedJwt,
        [NotNullWhen(true)] out string? nonce,
        [NotNullWhen(true)] out bool? ctsProfileMatch,
        [NotNullWhen(true)] out DateTimeOffset? timestamp)
    {
        if (validatedJwt is null)
        {
            nonce = null;
            ctsProfileMatch = null;
            timestamp = null;
            return false;
        }

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
