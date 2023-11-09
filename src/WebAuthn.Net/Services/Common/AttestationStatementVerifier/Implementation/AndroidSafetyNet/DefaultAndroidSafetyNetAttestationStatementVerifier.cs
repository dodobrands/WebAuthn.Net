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
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAndroidSafetyNetAttestationStatementVerifier<TContext>
    : IAndroidSafetyNetAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    private readonly IReadOnlySet<AttestationType> _supportedAttestationTypes = new HashSet<AttestationType>
    {
        AttestationType.Basic
    };

    public DefaultAndroidSafetyNetAttestationStatementVerifier(
        ITimeProvider timeProvider,
        IFidoAttestationCertificateInspector<TContext> fidoAttestationCertificateInspector)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(fidoAttestationCertificateInspector);
        TimeProvider = timeProvider;
        FidoAttestationCertificateInspector = fidoAttestationCertificateInspector;
    }

    protected ITimeProvider TimeProvider { get; }
    protected IFidoAttestationCertificateInspector<TContext> FidoAttestationCertificateInspector { get; }

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
        var certificatesToDispose = new List<X509Certificate2>();
        var keysToDispose = new List<AsymmetricAlgorithm>();
        try
        {
            // get x5c certificates for JWT validation
            if (!TryGetRawCertificates(jwt, out var trustPath))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var securityKeys = new List<SecurityKey>();
            foreach (var certBytes in trustPath)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(certBytes, out var certificate))
                {
                    certificate?.Dispose();
                    return Result<AttestationStatementVerificationResult>.Fail();
                }

                certificatesToDispose.Add(certificate);
                if (currentDate < certificate.NotBefore || currentDate > certificate.NotAfter)
                {
                    return Result<AttestationStatementVerificationResult>.Fail();
                }

                // get signing keys
                if (certificate.GetECDsaPublicKey() is { } ecdsaPublicKey)
                {
                    keysToDispose.Add(ecdsaPublicKey);
                    var key = new ECDsaSecurityKey(ecdsaPublicKey);
                    securityKeys.Add(key);
                }
                else if (certificate.GetRSAPublicKey() is { } rsaPublicKey)
                {
                    keysToDispose.Add(rsaPublicKey);
                    var parameters = rsaPublicKey.ExportParameters(false);
                    securityKeys.Add(new RsaSecurityKey(parameters));
                }
                else
                {
                    return Result<AttestationStatementVerificationResult>.Fail();
                }
            }

            var jwtValidationResult = await JwtValidator.ValidateAsync(jwtString, securityKeys, cancellationToken);
            if (!jwtValidationResult.IsValid)
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            if (jwtValidationResult.SecurityToken is not JwtSecurityToken validatedJwt)
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

            var attestationCert = certificatesToDispose.First();
            if (attestationCert.GetNameInfo(X509NameType.DnsName, false) is not "attest.android.com")
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            if (currentDate < timestamp.Value)
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            if (currentDate.Subtract(timestamp.Value) > TimeSpan.FromSeconds(60))
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            // 5) If successful, return implementation-specific values representing attestation type Basic and attestation trust path x5c.
            var acceptableTrustAnchorsResult = await GetAcceptableTrustAnchorsAsync(
                context,
                attestationCert,
                authenticatorData,
                cancellationToken);
            if (acceptableTrustAnchorsResult.HasError)
            {
                return Result<AttestationStatementVerificationResult>.Fail();
            }

            var result = new AttestationStatementVerificationResult(
                AttestationStatementFormat.AndroidSafetyNet,
                AttestationType.Basic,
                trustPath,
                acceptableTrustAnchorsResult.Ok);
            return Result<AttestationStatementVerificationResult>.Success(result);
        }
        finally
        {
            foreach (var key in keysToDispose)
            {
                key.Dispose();
            }

            foreach (var certificateToDispose in certificatesToDispose)
            {
                certificateToDispose.Dispose();
            }
        }
    }

    protected virtual async Task<Result<AcceptableTrustAnchors>> GetAcceptableTrustAnchorsAsync(
        TContext context,
        X509Certificate2 attestationCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rootCertificates = new UniqueByteArraysCollection();
        var embeddedCertificates = GetEmbeddedRootCertificates();
        rootCertificates.AddRange(embeddedCertificates);
        var inspectResult = await FidoAttestationCertificateInspector.InspectAttestationCertificateAsync(
            context,
            attestationCert,
            authenticatorData,
            GetSupportedAttestationTypes(),
            cancellationToken);
        if (inspectResult.HasError)
        {
            return Result<AcceptableTrustAnchors>.Fail();
        }

        if (inspectResult.Ok.HasValue)
        {
            var inspectionResult = inspectResult.Ok.Value;
            if (inspectionResult.AcceptableTrustAnchors is not null)
            {
                rootCertificates.AddRange(inspectionResult.AcceptableTrustAnchors.AttestationRootCertificates);
            }
        }

        return Result<AcceptableTrustAnchors>.Success(new(rootCertificates));
    }

    protected virtual IReadOnlySet<AttestationType> GetSupportedAttestationTypes()
    {
        return _supportedAttestationTypes;
    }

    protected virtual byte[][] GetEmbeddedRootCertificates()
    {
        return AndroidSafetyNetRoots.Certificates;
    }

    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetRawCertificates(JwtSecurityToken jwt, [NotNullWhen(true)] out byte[][]? rawCertificates)
    {
        if (jwt is null)
        {
            rawCertificates = null;
            return false;
        }

        if (!jwt.Header.TryGetValue("x5c", out var certificatesObject) || certificatesObject is null)
        {
            rawCertificates = null;
            return false;
        }

        if (certificatesObject is string certificatesString)
        {
            var rawCert = WebEncoders.Base64UrlDecode(certificatesString);
            rawCertificates = new[] { rawCert };
            return true;
        }

        if (certificatesObject is IEnumerable certificatesEnumerable)
        {
            var result = new List<byte[]>();
            foreach (var certificateObject in certificatesEnumerable)
            {
                if (certificateObject is not string certificateString)
                {
                    rawCertificates = null;
                    return false;
                }

                var rawCert = WebEncoders.Base64UrlDecode(certificateString);
                result.Add(rawCert);
            }

            if (result.Count == 0)
            {
                rawCertificates = null;
                return false;
            }

            rawCertificates = result.ToArray();
            return true;
        }

        rawCertificates = null;
        return false;
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
