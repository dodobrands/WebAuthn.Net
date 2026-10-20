using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
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

/// <summary>
///     Default implementation of <see cref="IAndroidSafetyNetAttestationStatementVerifier{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultAndroidSafetyNetAttestationStatementVerifier<TContext>
    : IAndroidSafetyNetAttestationStatementVerifier<TContext> where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     The maximum number of certificates accepted in the 'x5c' header of the JWS: a legitimate chain (leaf, intermediates, root) is far shorter, and every certificate is loaded and parsed before any signature is verified.
    /// </summary>
    protected const int MaxX5CCertificates = 16;

    /// <summary>
    ///     The largest Unix time in milliseconds that <see cref="DateTimeOffset" /> can represent (9999-12-31T23:59:59.999Z).
    /// </summary>
    private const long MaxUnixTimeMilliseconds = 253_402_300_799_999;

    /// <summary>
    ///     Constructs <see cref="DefaultAndroidSafetyNetAttestationStatementVerifier{TContext}" />.
    /// </summary>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="safeJsonSerializer">Safe (exceptionless) JSON serializer.</param>
    /// <param name="fidoMetadataSearchService">A service for searching in the data provided by the FIDO Metadata Service.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidSafetyNetAttestationStatementVerifier(
        ITimeProvider timeProvider,
        ISafeJsonSerializer safeJsonSerializer,
        IFidoMetadataSearchService<TContext> fidoMetadataSearchService,
        ILogger<DefaultAndroidSafetyNetAttestationStatementVerifier<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(safeJsonSerializer);
        ArgumentNullException.ThrowIfNull(fidoMetadataSearchService);
        ArgumentNullException.ThrowIfNull(logger);
        TimeProvider = timeProvider;
        SafeJsonSerializer = safeJsonSerializer;
        FidoMetadataSearchService = fidoMetadataSearchService;
        Logger = logger;
    }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Safe (exceptionless) JSON serializer.
    /// </summary>
    protected ISafeJsonSerializer SafeJsonSerializer { get; }

    /// <summary>
    ///     A service for searching in the data provided by the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchService<TContext> FidoMetadataSearchService { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAndroidSafetyNetAttestationStatementVerifier<TContext>> Logger { get; }

    /// <inheritdoc />
    [SuppressMessage("Security", "CA5404:Do not disable token validation checks")]
    public virtual async Task<Result<VerifiedAttestationStatement>> VerifyAsync(
        TContext context,
        AndroidSafetyNetAttestationStatement attStmt,
        AttestedAuthenticatorData authenticatorData,
        byte[] clientDataHash,
        CancellationToken cancellationToken)
    {
        // https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation
        // "Android SafetyNet Attestation Statement Format"

        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(attStmt);
        ArgumentNullException.ThrowIfNull(authenticatorData);
        ArgumentNullException.ThrowIfNull(clientDataHash);
        // 1) Verify that 'attStmt' is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.
        // 2) Verify that 'response' is a valid SafetyNet response of version 'ver' by following the steps indicated by the SafetyNet online documentation.
        // As of this writing, there is only one format of the SafetyNet response and ver is reserved for future use.
        // (TryParseJws logs the reason when 'response' is not a JWS in compact serialization)
        if (!TryParseJws(attStmt.Response, out var jwtString, out var jwt))
        {
            return Result<VerifiedAttestationStatement>.Fail();
        }

        var certificatesToDispose = new List<X509Certificate2>();
        var keysToDispose = new List<AsymmetricAlgorithm>();
        try
        {
            // get x5c certificates for JWT validation
            // (TryGetRawCertificates logs the reason when the 'x5c' header is missing or invalid)
            if (!TryGetRawCertificates(jwt, out var trustPath))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (trustPath.Length == 0)
            {
                Logger.AndroidSafetyNetX5CEmpty();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var securityKeys = new List<SecurityKey>();
            foreach (var certBytes in trustPath)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(certBytes, out var certificate))
                {
                    certificate?.Dispose();
                    Logger.AndroidSafetyNetX5CCertificateInvalid();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                certificatesToDispose.Add(certificate);
                if (currentDate < certificate.NotBefore || currentDate > certificate.NotAfter)
                {
                    Logger.AndroidSafetyNetX5CCertificateNotValidNow();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                // get signing keys
                if (!TryGetSecurityKey(certificate, keysToDispose, out var securityKey))
                {
                    Logger.AndroidSafetyNetX5CCertificatePublicKeyNotSupported();
                    return Result<VerifiedAttestationStatement>.Fail();
                }

                securityKeys.Add(securityKey);
            }

            // the JWS comes from the client, so it is validated with the default size limit of the token handler instead of a limit derived from its own length
            var jwtValidationResult = await JwtValidator.ValidateAsync(jwtString, securityKeys, TokenValidationParameters.DefaultMaximumTokenSizeInBytes, cancellationToken);
            if (!jwtValidationResult.IsValid)
            {
                Logger.AndroidSafetyNetJwsSignatureInvalid(jwtValidationResult.Exception);
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (jwtValidationResult.SecurityToken is not JwtSecurityToken validatedJwt)
            {
                Logger.AndroidSafetyNetJwsValidatedTokenInvalid();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // (TryGetRequiredClaims logs the reason when a required claim is missing or invalid)
            if (!TryGetRequiredClaims(validatedJwt, out var nonce, out var ctsProfileMatch, out var timestamp))
            {
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 3) Verify that the 'nonce' attribute in the payload of response
            // is identical to the Base64 encoding of the SHA-256 hash of the concatenation of 'authenticatorData' and 'clientDataHash'.
            var dataToVerify = SHA256.HashData(Concat(authenticatorData.Raw, clientDataHash));
            if (!Base64Raw.TryDecode(nonce, out var binaryNonce))
            {
                Logger.AndroidSafetyNetNonceNotBase64();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (!binaryNonce.AsSpan().SequenceEqual(dataToVerify.AsSpan()))
            {
                Logger.AndroidSafetyNetNonceMismatch();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            // 4) Verify that the SafetyNet response actually came from the SafetyNet service by following the steps in the SafetyNet online documentation.
            if (!ctsProfileMatch.Value)
            {
                Logger.AndroidSafetyNetCtsProfileMatchFalse();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            var attestationCert = certificatesToDispose.First();
            if (!IsIssuedToAttestAndroidCom(attestationCert))
            {
                Logger.AndroidSafetyNetHostnameMismatch();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (currentDate < timestamp.Value)
            {
                Logger.AndroidSafetyNetTimestampInFuture();
                return Result<VerifiedAttestationStatement>.Fail();
            }

            if (currentDate.Subtract(timestamp.Value) > TimeSpan.FromSeconds(60))
            {
                Logger.AndroidSafetyNetTimestampTooOld();
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
                Logger.AndroidSafetyNetTrustAnchorsUnavailable();
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

    /// <summary>
    ///     Parses the 'response' of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a> as a JWS in compact serialization, without validating it.
    /// </summary>
    /// <param name="response">The 'response' of the attestation statement: the UTF-8 encoded JWS.</param>
    /// <param name="jwtString">Output parameter. If the method returns <see langword="true" /> - the JWS as a string, otherwise - <see langword="null" />.</param>
    /// <param name="jwt">Output parameter. If the method returns <see langword="true" /> - the parsed (not yet validated) JWS, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the 'response' is a JWS in compact serialization that is not larger than <see cref="TokenValidationParameters.DefaultMaximumTokenSizeInBytes" />, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "The token handler reports a malformed token with several exception types (SecurityTokenMalformedException, ArgumentException, ...); any of them means that the client-supplied 'response' is not a JWS, which is a verification failure")]
    protected virtual bool TryParseJws(byte[] response, [NotNullWhen(true)] out string? jwtString, [NotNullWhen(true)] out JwtSecurityToken? jwt)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (response is null)
        {
            jwtString = null;
            jwt = null;
            return false;
        }

        // the size limit is applied before anything is decoded: the token handler would apply the same limit, but only after the JWS has been parsed
        if (response.Length > TokenValidationParameters.DefaultMaximumTokenSizeInBytes)
        {
            Logger.AndroidSafetyNetResponseTooLarge(response.Length, TokenValidationParameters.DefaultMaximumTokenSizeInBytes);
            jwtString = null;
            jwt = null;
            return false;
        }

        var decodedJwtString = Encoding.UTF8.GetString(response);
        try
        {
            // the constructor parses the compact serialization and throws for anything that is not a JWS (wrong number of segments, invalid base64url, invalid JSON in the header or the payload)
            jwt = new JwtSecurityToken(decodedJwtString);
            jwtString = decodedJwtString;
            return true;
        }
        catch (Exception exception)
        {
            Logger.AndroidSafetyNetResponseNotJws(exception);
            jwtString = null;
            jwt = null;
            return false;
        }
    }

    /// <summary>
    ///     Returns the public key of the certificate as a <see cref="SecurityKey" /> for the validation of the JWS signature.
    /// </summary>
    /// <param name="certificate">A certificate from the 'x5c' header of the JWS.</param>
    /// <param name="keysToDispose">The collection to which the created <see cref="AsymmetricAlgorithm" /> is added, so that the caller can dispose it.</param>
    /// <param name="securityKey">Output parameter. If the method returns <see langword="true" /> - the public key of the certificate, otherwise - <see langword="null" />.</param>
    /// <returns><see langword="true" /> if the certificate contains an ECDSA or RSA public key that can be used for the validation of the JWS signature, otherwise - <see langword="false" />.</returns>
    protected virtual bool TryGetSecurityKey(X509Certificate2 certificate, ICollection<AsymmetricAlgorithm> keysToDispose, [NotNullWhen(true)] out SecurityKey? securityKey)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(keysToDispose);
        try
        {
            if (certificate.GetECDsaPublicKey() is { } ecdsaPublicKey)
            {
                keysToDispose.Add(ecdsaPublicKey);
                securityKey = new ECDsaSecurityKey(ecdsaPublicKey);
                return true;
            }

            if (certificate.GetRSAPublicKey() is { } rsaPublicKey)
            {
                keysToDispose.Add(rsaPublicKey);
                var parameters = rsaPublicKey.ExportParameters(false);
                securityKey = new RsaSecurityKey(parameters);
                return true;
            }
        }
        catch (CryptographicException)
        {
            // the certificate comes from the client: a public key the platform cannot export is a verification failure, not an exception
        }

        securityKey = null;
        return false;
    }

    /// <summary>
    ///     Verifies that the leaf certificate of the JWS was issued to the hostname "attest.android.com".
    /// </summary>
    /// <param name="attestationCert">The leaf certificate from the certificate chain of the JWS message of the Android SafetyNet attestation statement.</param>
    /// <returns><see langword="true" /> if the certificate was issued to the hostname "attest.android.com", otherwise - <see langword="false" />.</returns>
    protected virtual bool IsIssuedToAttestAndroidCom(X509Certificate2 attestationCert)
    {
        ArgumentNullException.ThrowIfNull(attestationCert);
        try
        {
            return attestationCert.GetNameInfo(X509NameType.DnsName, false) is "attest.android.com";
        }
        catch (CryptographicException)
        {
            // the certificate comes from the client: a name the platform cannot decode is a verification failure, not an exception
            return false;
        }
    }

    /// <summary>
    ///     Returns a collection of valid root X509v3 certificates.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="attestationCert">The leaf certificate from the certificate chain of the JWS message of the Android SafetyNet attestation statement.</param>
    /// <param name="authenticatorData"><a href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">Authenticator data</a> that has <a href="https://www.w3.org/TR/webauthn-3/#authdata-attestedcredentialdata">attestedCredentialData</a>.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the collection of root certificates was successfully formed, the result contains <see cref="UniqueByteArraysCollection" />, otherwise the result indicates that there was an error during the collection formation process.</returns>
    protected virtual async Task<Result<UniqueByteArraysCollection>> GetAcceptableTrustAnchorsAsync(
        TContext context,
        X509Certificate2 attestationCert,
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

        if (metadataRoots is not null)
        {
            rootCertificates.AddRange(metadataRoots);
        }

        return Result<UniqueByteArraysCollection>.Success(new(rootCertificates));
    }

    /// <summary>
    ///     Returns a collection of valid root certificates from the Fido Metadata Service.
    /// </summary>
    /// <param name="context">The context in which the WebAuthn operation is performed.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns>If the Fido Metadata Service contains root certificates for the specified <paramref name="aaguid" /> - then <see cref="UniqueByteArraysCollection" />, otherwise - <see langword="null" />.</returns>
    protected virtual async Task<UniqueByteArraysCollection?> GetAcceptableTrustAnchorsFromFidoMetadataAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var metadata = await FidoMetadataSearchService.FindMetadataByAaguidAsync(context, aaguid, cancellationToken);
        if (metadata is null)
        {
            return null;
        }

        if (metadata.AttestationTypes.Contains(AuthenticatorAttestationType.ATTESTATION_BASIC_FULL))
        {
            var result = new UniqueByteArraysCollection();
            // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
            if (metadata.RootCertificates?.Length > 0)
            {
                result.AddRange(metadata.RootCertificates);
            }

            return result;
        }

        return null;
    }

    /// <summary>
    ///     Returns a collection of root certificates embedded in the library.
    /// </summary>
    /// <returns>An instance of <see cref="UniqueByteArraysCollection" />. It may return an empty collection, but it never returns <see langword="null" />.</returns>
    protected virtual UniqueByteArraysCollection GetEmbeddedRootCertificates()
    {
        return new(AndroidSafetyNetRoots.Certificates);
    }

    /// <summary>
    ///     Returns X509v3 certificates from the header of the JWS token of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
    /// </summary>
    /// <param name="jwt">
    ///     JWT (JWS) token of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
    /// </param>
    /// <param name="rawCertificates">Output parameter. If the method returns <see langword="true" /> - contains X509v3 certificates in the order they appear in the JWS token header, if the method return <see langword="false" />, contains <see langword="null" />.</param>
    /// <returns>If the extraction of certificates from the header was successful, returns <see langword="true" />, otherwise, returns <see langword="false" />. </returns>
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
            Logger.AndroidSafetyNetJwsHeaderNotBase64Url();
            rawCertificates = null;
            return false;
        }

        var headerResult = SafeJsonSerializer.DeserializeNonNullable<JsonDocument>(utf8Bytes);
        if (headerResult.HasError)
        {
            Logger.AndroidSafetyNetJwsHeaderNotJson();
            rawCertificates = null;
            return false;
        }

        using var header = headerResult.Ok;
        if (!header.RootElement.TryGetProperty("x5c", out var x5CJson))
        {
            Logger.AndroidSafetyNetJwsHeaderX5CNotFound();
            rawCertificates = null;
            return false;
        }

        if (x5CJson.ValueKind == JsonValueKind.String)
        {
            var base64Certificate = x5CJson.GetString();
            if (string.IsNullOrEmpty(base64Certificate))
            {
                Logger.AndroidSafetyNetJwsHeaderX5CElementInvalid();
                rawCertificates = null;
                return false;
            }

            if (!Base64Raw.TryDecode(base64Certificate, out var rawCert))
            {
                Logger.AndroidSafetyNetJwsHeaderX5CElementInvalid();
                rawCertificates = null;
                return false;
            }

            if (rawCert.Length == 0)
            {
                Logger.AndroidSafetyNetJwsHeaderX5CElementInvalid();
                rawCertificates = null;
                return false;
            }

            rawCertificates = new[] { rawCert };
            return true;
        }

        if (x5CJson.ValueKind == JsonValueKind.Array)
        {
            var x5CLength = x5CJson.GetArrayLength();
            if (x5CLength > MaxX5CCertificates)
            {
                Logger.AndroidSafetyNetJwsHeaderX5CTooManyElements(x5CLength, MaxX5CCertificates);
                rawCertificates = null;
                return false;
            }

            var result = new List<byte[]>(x5CLength);
            foreach (var x5CElement in x5CJson.EnumerateArray())
            {
                if (x5CElement.ValueKind != JsonValueKind.String)
                {
                    Logger.AndroidSafetyNetJwsHeaderX5CElementInvalid();
                    rawCertificates = null;
                    return false;
                }

                var base64Certificate = x5CElement.GetString();
                if (string.IsNullOrEmpty(base64Certificate))
                {
                    Logger.AndroidSafetyNetJwsHeaderX5CElementInvalid();
                    rawCertificates = null;
                    return false;
                }

                if (!Base64Raw.TryDecode(base64Certificate, out var rawCert))
                {
                    Logger.AndroidSafetyNetJwsHeaderX5CElementInvalid();
                    rawCertificates = null;
                    return false;
                }

                if (rawCert.Length == 0)
                {
                    Logger.AndroidSafetyNetJwsHeaderX5CElementInvalid();
                    rawCertificates = null;
                    return false;
                }

                result.Add(rawCert);
            }

            rawCertificates = result.ToArray();
            return true;
        }

        Logger.AndroidSafetyNetJwsHeaderX5CInvalidDataType();
        rawCertificates = null;
        return false;
    }

    /// <summary>
    ///     Extracts the required claims from the validated JWT (JWS) token of the <a href="https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation">Android SafetyNet attestation statement</a>.
    /// </summary>
    /// <param name="validatedJwt">The validated JWS (JWT) token of Android SafetyNet attestation statement.</param>
    /// <param name="nonce">Output parameter that contains a value only if the method returns true. The single-use token that the calling app passes to the API.</param>
    /// <param name="ctsProfileMatch">
    ///     Output parameter that contains a value only if the method returns true. A stricter verdict of device integrity. If the value of ctsProfileMatch is <see langword="true" />, then the profile of the device running your app matches the profile of a
    ///     device that has passed Android compatibility testing and has been approved as a Google-certified Android device.
    /// </param>
    /// <param name="timestamp">Output parameter that contains a value only if the method returns true. The time when the JWS response message was generated by Google's servers.</param>
    /// <returns>If all claims are found and extracted - returns <see langword="true" />, otherwise - <see langword="false" />.</returns>
    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "The claims are materialized from the client-supplied payload by the token handler; a payload it cannot represent as claims is a verification failure, not an exception")]
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

        try
        {
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
                else if (claim is { Type: "timestampMs", Value.Length: > 0 } && long.TryParse(claim.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedTimestampMs))
                {
                    // the value comes from the client: only the range that DateTimeOffset can represent (and that is not before the Unix epoch) is converted, anything else is treated as an absent claim
                    if (parsedTimestampMs is < 0 or > MaxUnixTimeMilliseconds)
                    {
                        Logger.AndroidSafetyNetTimestampOutOfRange(parsedTimestampMs);
                        nonce = null;
                        ctsProfileMatch = null;
                        timestamp = null;
                        return false;
                    }

                    resultTimestamp = DateTimeOffset.FromUnixTimeMilliseconds(parsedTimestampMs);
                }
            }
        }
        catch (Exception exception)
        {
            Logger.AndroidSafetyNetClaimsNotReadable(exception);
            nonce = null;
            ctsProfileMatch = null;
            timestamp = null;
            return false;
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

        Logger.AndroidSafetyNetRequiredClaimsMissing(resultNonce is not null, resultCtsProfileMatch.HasValue, resultTimestamp.HasValue);
        nonce = null;
        ctsProfileMatch = null;
        timestamp = null;
        return false;
    }


    /// <summary>
    ///     Concatenates two ReadOnlySpan of bytes into one array.
    /// </summary>
    /// <param name="a">First ReadOnlySpan of bytes.</param>
    /// <param name="b">Second ReadOnlySpan of bytes.</param>
    /// <returns>An array of bytes, filled with the content of the passed ReadOnlySpans.</returns>
    protected virtual byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var result = new byte[a.Length + b.Length];
        a.CopyTo(result);
        b.CopyTo(result.AsSpan(a.Length));
        return result;
    }
}

/// <summary>
///     Extension methods for logging the Android SafetyNet attestation statement verifier.
/// </summary>
public static partial class DefaultAndroidSafetyNetAttestationStatementVerifierLoggingExtensions
{
    /// <summary>
    ///     The 'response' of the Android SafetyNet attestation statement is {Length} byte(s) long, which exceeds the maximum accepted JWS size of {MaxLength} byte(s)
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="length">The length of the 'response'.</param>
    /// <param name="maxLength">The maximum accepted length.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'response' of the Android SafetyNet attestation statement is {Length} byte(s) long, which exceeds the maximum accepted JWS size of {MaxLength} byte(s)")]
    public static partial void AndroidSafetyNetResponseTooLarge(this ILogger logger, int length, int maxLength);

    /// <summary>
    ///     The 'response' of the Android SafetyNet attestation statement is not a JWS in compact serialization
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception thrown by the token handler.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'response' of the Android SafetyNet attestation statement is not a JWS in compact serialization")]
    public static partial void AndroidSafetyNetResponseNotJws(this ILogger logger, Exception exception);

    /// <summary>
    ///     The header of the JWS of the Android SafetyNet attestation statement is not valid base64url
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The header of the JWS of the Android SafetyNet attestation statement is not valid base64url")]
    public static partial void AndroidSafetyNetJwsHeaderNotBase64Url(this ILogger logger);

    /// <summary>
    ///     The header of the JWS of the Android SafetyNet attestation statement is not a JSON object
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The header of the JWS of the Android SafetyNet attestation statement is not a JSON object")]
    public static partial void AndroidSafetyNetJwsHeaderNotJson(this ILogger logger);

    /// <summary>
    ///     The header of the JWS of the Android SafetyNet attestation statement does not contain the 'x5c' parameter
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The header of the JWS of the Android SafetyNet attestation statement does not contain the 'x5c' parameter")]
    public static partial void AndroidSafetyNetJwsHeaderX5CNotFound(this ILogger logger);

    /// <summary>
    ///     The 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is neither a string nor an array
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is neither a string nor an array")]
    public static partial void AndroidSafetyNetJwsHeaderX5CInvalidDataType(this ILogger logger);

    /// <summary>
    ///     An element of the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is not a non-empty base64-encoded certificate
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "An element of the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is not a non-empty base64-encoded certificate")]
    public static partial void AndroidSafetyNetJwsHeaderX5CElementInvalid(this ILogger logger);

    /// <summary>
    ///     The 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement contains {Count} certificates, which exceeds the maximum of {MaxCount}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of certificates in 'x5c'.</param>
    /// <param name="maxCount">The maximum number of certificates accepted in 'x5c'.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement contains {Count} certificates, which exceeds the maximum of {MaxCount}")]
    public static partial void AndroidSafetyNetJwsHeaderX5CTooManyElements(this ILogger logger, int count, int maxCount);

    /// <summary>
    ///     The 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is empty
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is empty")]
    public static partial void AndroidSafetyNetX5CEmpty(this ILogger logger);

    /// <summary>
    ///     Failed to load a certificate from the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to load a certificate from the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement")]
    public static partial void AndroidSafetyNetX5CCertificateInvalid(this ILogger logger);

    /// <summary>
    ///     A certificate from the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is not valid at the current time
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "A certificate from the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement is not valid at the current time")]
    public static partial void AndroidSafetyNetX5CCertificateNotValidNow(this ILogger logger);

    /// <summary>
    ///     A certificate from the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement has neither an ECDSA nor an RSA public key usable for the signature validation
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "A certificate from the 'x5c' parameter in the header of the JWS of the Android SafetyNet attestation statement has neither an ECDSA nor an RSA public key usable for the signature validation")]
    public static partial void AndroidSafetyNetX5CCertificatePublicKeyNotSupported(this ILogger logger);

    /// <summary>
    ///     The JWS of the Android SafetyNet attestation statement failed validation: its signature is not valid for any of the 'x5c' certificates, or its algorithm is not acceptable
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception reported by the token handler, if any.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The JWS of the Android SafetyNet attestation statement failed validation: its signature is not valid for any of the 'x5c' certificates, or its algorithm is not acceptable")]
    public static partial void AndroidSafetyNetJwsSignatureInvalid(this ILogger logger, Exception? exception);

    /// <summary>
    ///     The token handler validated the JWS of the Android SafetyNet attestation statement but did not return a JwtSecurityToken
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The token handler validated the JWS of the Android SafetyNet attestation statement but did not return a JwtSecurityToken")]
    public static partial void AndroidSafetyNetJwsValidatedTokenInvalid(this ILogger logger);

    /// <summary>
    ///     The claims of the JWS of the Android SafetyNet attestation statement cannot be read
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception thrown while reading the claims.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The claims of the JWS of the Android SafetyNet attestation statement cannot be read")]
    public static partial void AndroidSafetyNetClaimsNotReadable(this ILogger logger, Exception exception);

    /// <summary>
    ///     The 'timestampMs' claim of the Android SafetyNet attestation statement is out of range: {TimestampMs}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="timestampMs">The value of the claim.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'timestampMs' claim of the Android SafetyNet attestation statement is out of range: {TimestampMs}")]
    public static partial void AndroidSafetyNetTimestampOutOfRange(this ILogger logger, long timestampMs);

    /// <summary>
    ///     The JWS of the Android SafetyNet attestation statement lacks a required claim (nonce present: {NoncePresent}, ctsProfileMatch present: {CtsProfileMatchPresent}, timestampMs present: {TimestampPresent})
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="noncePresent">Whether a non-empty 'nonce' claim is present.</param>
    /// <param name="ctsProfileMatchPresent">Whether a boolean 'ctsProfileMatch' claim is present.</param>
    /// <param name="timestampPresent">Whether an integer 'timestampMs' claim is present.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The JWS of the Android SafetyNet attestation statement lacks a required claim (nonce present: {NoncePresent}, ctsProfileMatch present: {CtsProfileMatchPresent}, timestampMs present: {TimestampPresent})")]
    public static partial void AndroidSafetyNetRequiredClaimsMissing(this ILogger logger, bool noncePresent, bool ctsProfileMatchPresent, bool timestampPresent);

    /// <summary>
    ///     The 'nonce' claim of the Android SafetyNet attestation statement is not valid base64
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'nonce' claim of the Android SafetyNet attestation statement is not valid base64")]
    public static partial void AndroidSafetyNetNonceNotBase64(this ILogger logger);

    /// <summary>
    ///     The 'nonce' claim of the Android SafetyNet attestation statement is not equal to SHA-256(authenticatorData || clientDataHash)
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'nonce' claim of the Android SafetyNet attestation statement is not equal to SHA-256(authenticatorData || clientDataHash)")]
    public static partial void AndroidSafetyNetNonceMismatch(this ILogger logger);

    /// <summary>
    ///     The 'ctsProfileMatch' claim of the Android SafetyNet attestation statement is false
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'ctsProfileMatch' claim of the Android SafetyNet attestation statement is false")]
    public static partial void AndroidSafetyNetCtsProfileMatchFalse(this ILogger logger);

    /// <summary>
    ///     The leaf certificate of the JWS of the Android SafetyNet attestation statement was not issued to the hostname "attest.android.com"
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The leaf certificate of the JWS of the Android SafetyNet attestation statement was not issued to the hostname \"attest.android.com\"")]
    public static partial void AndroidSafetyNetHostnameMismatch(this ILogger logger);

    /// <summary>
    ///     The 'timestampMs' claim of the Android SafetyNet attestation statement is in the future
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'timestampMs' claim of the Android SafetyNet attestation statement is in the future")]
    public static partial void AndroidSafetyNetTimestampInFuture(this ILogger logger);

    /// <summary>
    ///     The 'timestampMs' claim of the Android SafetyNet attestation statement is more than 60 seconds old
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'timestampMs' claim of the Android SafetyNet attestation statement is more than 60 seconds old")]
    public static partial void AndroidSafetyNetTimestampTooOld(this ILogger logger);

    /// <summary>
    ///     The acceptable trust anchors for the Android SafetyNet attestation statement could not be determined
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The acceptable trust anchors for the Android SafetyNet attestation statement could not be determined")]
    public static partial void AndroidSafetyNetTrustAnchorsUnavailable(this ILogger logger);
}
