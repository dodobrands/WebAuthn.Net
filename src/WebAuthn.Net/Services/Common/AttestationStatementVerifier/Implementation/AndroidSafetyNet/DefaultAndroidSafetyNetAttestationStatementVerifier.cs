using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Abstractions.AndroidSafetyNet;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet.Constants;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.AttestationStatementVerifier;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Models.Enums;
using WebAuthn.Net.Services.Common.AuthenticatorDataDecoder.Models;
using WebAuthn.Net.Services.FidoMetadata;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidSafetyNet;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAndroidSafetyNetAttestationStatementVerifier<TContext>
    : IAndroidSafetyNetAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    public DefaultAndroidSafetyNetAttestationStatementVerifier(
        ITimeProvider timeProvider,
        ISafeJsonSerializer safeJsonSerializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(safeJsonSerializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        TimeProvider = timeProvider;
        SafeJsonSerializer = safeJsonSerializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
    }

    protected ITimeProvider TimeProvider { get; }
    protected ISafeJsonSerializer SafeJsonSerializer { get; }
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    [SuppressMessage("Security", "CA5404:Do not disable token validation checks")]
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
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
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (trustPath.Length == 0)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var securityKeys = new List<SecurityKey>();
            foreach (var certBytes in trustPath)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(certBytes, out var certificate))
                {
                    certificate?.Dispose();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                certificatesToDispose.Add(certificate);
                if (currentDate < certificate.NotBefore || currentDate > certificate.NotAfter)
                {
                    return Result<VerifiedAttestationStatement>.Fail();
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
                    return Result<VerifiedAttestationStatement>.Fail();
                }
            }

            var jwtValidationResult = await JwtValidator.ValidateAsync(jwtString, securityKeys, cancellationToken);
            if (!jwtValidationResult.IsValid)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (jwtValidationResult.SecurityToken is not JwtSecurityToken validatedJwt)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!TryGetRequiredClaims(validatedJwt, out var nonce, out var ctsProfileMatch, out var timestamp))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 3) Verify that the 'nonce' attribute in the payload of response
            // is identical to the Base64 encoding of the SHA-256 hash of the concatenation of 'authenticatorData' and 'clientDataHash'.
            var dataToVerify = SHA256.HashData(Concat(authenticatorData.Raw, clientDataHash));
            if (!Base64Raw.TryDecode(nonce, out var binaryNonce))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!binaryNonce.AsSpan().SequenceEqual(dataToVerify.AsSpan()))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4) Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the SafetyNet online documentation.
            if (ctsProfileMatch.Value != true)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var attestationCert = certificatesToDispose.First();
            if (attestationCert.GetNameInfo(X509NameType.DnsName, false) is not "attest.android.com")
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (currentDate < timestamp.Value)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (currentDate.Subtract(timestamp.Value) > TimeSpan.FromSeconds(60))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 5) If successful, return implementation-specific values representing attestation type Basic and attestation trust path x5c.
            var acceptableTrustAnchorsResult = await GetAcceptableTrustAnchorsAsync(
                context,
                attestationCert,
                authenticatorData,
                cancellationToken);
            if (acceptableTrustAnchorsResult.HasError)
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var result = new VerifiedAttestationStatement(
                AttestationStatementFormat.AndroidSafetyNet,
                AttestationType.Basic,
                trustPath,
                acceptableTrustAnchorsResult.Ok);
            return Result<VerifiedAttestationStatement>.Success(result);
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

    protected virtual async Task<Result<UniqueByteArraysCollection>> GetAcceptableTrustAnchorsAsync(
        TContext context,
        X509Certificate2 credCert,
        AttestedAuthenticatorData authenticatorData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authenticatorData);
        cancellationToken.ThrowIfCancellationRequested();

        var rootCertificates = new UniqueByteArraysCollection();
        var embeddedCertificates = GetEmbeddedRootCertificates();
        rootCertificates.AddRange(embeddedCertificates);
        var metadataRoots = await GetAcceptableTrustAnchorsFromFidoMetadataAsync(
            context,
            authenticatorData.AttestedCredentialData.Aaguid,
            cancellationToken);

        if (metadataRoots.HasValue)
        {
            rootCertificates.AddRange(metadataRoots.Value);
        }

        return Result<UniqueByteArraysCollection>.Success(new(rootCertificates));
    }

    protected virtual async Task<Optional<byte[][]>> GetAcceptableTrustAnchorsFromFidoMetadataAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadataResult = await FidoMetadataSearchService.FindMetadataByAaguidAsync(context, aaguid, cancellationToken);
        if (!metadataResult.HasValue)
        {
            return Optional<byte[][]>.Empty();
        }

        var metadata = metadataResult.Value;
        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            return Optional<byte[][]>.Payload(metadata.RootCertificates);
        }

        return Optional<byte[][]>.Empty();
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

    protected virtual bool TryGetRawCertificates(JwtSecurityToken jwt, [NotNullWhen(true)] out byte[][]? rawCertificates)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (jwt is null)
        {
            rawCertificates = null;
            return false;
        }

        if (!Base64Url.TryDecode(jwt.EncodedHeader, out var utf8Bytes))
        {
            rawCertificates = null;
            return false;
        }

        var headerResult = SafeJsonSerializer.DeserializeNonNullable<JsonDocument>(utf8Bytes);
        if (headerResult.HasError)
        {
            rawCertificates = null;
            return false;
        }

        using var header = headerResult.Ok;
        if (!header.RootElement.TryGetProperty("x5c", out var x5CJson))
        {
            rawCertificates = null;
            return false;
        }

        if (x5CJson.ValueKind == JsonValueKind.String)
        {
            var base64Certificate = x5CJson.GetString();
            if (string.IsNullOrEmpty(base64Certificate))
            {
                rawCertificates = null;
                return false;
            }

            if (!Base64Raw.TryDecode(base64Certificate, out var rawCert))
            {
                rawCertificates = null;
                return false;
            }

            rawCertificates = new[] { rawCert };
            return true;
        }

        if (x5CJson.ValueKind == JsonValueKind.Array)
        {
            var result = new List<byte[]>();
            foreach (var x5CElement in x5CJson.EnumerateArray())
            {
                if (x5CElement.ValueKind != JsonValueKind.String)
                {
                    rawCertificates = null;
                    return false;
                }

                var base64Certificate = x5CElement.GetString();
                if (string.IsNullOrEmpty(base64Certificate))
                {
                    rawCertificates = null;
                    return false;
                }

                if (!Base64Raw.TryDecode(base64Certificate, out var rawCert))
                {
                    rawCertificates = null;
                    return false;
                }

                if (rawCert.Length == 0)
                {
                    rawCertificates = null;
                    return false;
                }

                result.Add(rawCert);
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
