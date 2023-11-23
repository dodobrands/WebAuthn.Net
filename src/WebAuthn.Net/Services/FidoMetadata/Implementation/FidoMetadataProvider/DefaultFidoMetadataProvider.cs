using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultFidoMetadataProvider : IFidoMetadataProvider
{
    public DefaultFidoMetadataProvider(
        IOptionsMonitor<WebAuthnOptions> options,
        ISafeJsonSerializer safeJsonSerializer,
        IFidoMetadataHttpClient metadataHttpClient,
        ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(safeJsonSerializer);
        ArgumentNullException.ThrowIfNull(metadataHttpClient);
        ArgumentNullException.ThrowIfNull(timeProvider);
        Options = options;
        SafeJsonSerializer = safeJsonSerializer;
        MetadataHttpClient = metadataHttpClient;
        TimeProvider = timeProvider;
    }

    protected IOptionsMonitor<WebAuthnOptions> Options { get; }
    protected ISafeJsonSerializer SafeJsonSerializer { get; }
    protected IFidoMetadataHttpClient MetadataHttpClient { get; }
    protected ITimeProvider TimeProvider { get; }

    [SuppressMessage("Security", "CA5404:Do not disable token validation checks")]
    public virtual async Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var certificatesToDispose = new List<X509Certificate2>();
        var keysToDispose = new List<AsymmetricAlgorithm>();
        try
        {
            var rawMetadata = await MetadataHttpClient.DownloadMetadataAsync(cancellationToken);
            var jwt = new JsonWebToken(rawMetadata);
            if (!TryGetRawCertificates(jwt, out var headerCertificates))
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            if (headerCertificates.Length == 0)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var jwtCertificates = new List<X509Certificate2>();
            foreach (var certBytes in headerCertificates)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(certBytes, out var jwtCertificate))
                {
                    jwtCertificate?.Dispose();
                    return Result<MetadataBLOBPayloadJSON>.Fail();
                }

                certificatesToDispose.Add(jwtCertificate);
                jwtCertificates.Add(jwtCertificate);
                if (currentDate < jwtCertificate.NotBefore || currentDate > jwtCertificate.NotAfter)
                {
                    return Result<MetadataBLOBPayloadJSON>.Fail();
                }
            }

            // build root certificates chain that avoid expired certificates
            var fidoRootCertificates = GetFidoMetadataRootCertificates();
            if (fidoRootCertificates.Length == 0)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            var rootCertificates = new List<X509Certificate2>();
            foreach (var fidoRootCertBytes in fidoRootCertificates)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(fidoRootCertBytes, out var fidoRootCertificate))
                {
                    fidoRootCertificate?.Dispose();
                    return Result<MetadataBLOBPayloadJSON>.Fail();
                }

                certificatesToDispose.Add(fidoRootCertificate);
                if (currentDate >= fidoRootCertificate.NotBefore && currentDate <= fidoRootCertificate.NotAfter)
                {
                    rootCertificates.Add(fidoRootCertificate);
                }
            }

            var securityKeys = new List<SecurityKey>();
            foreach (var jwtCertificate in jwtCertificates)
            {
                if (jwtCertificate.GetECDsaPublicKey() is { } ecdsaPublicKey)
                {
                    keysToDispose.Add(ecdsaPublicKey);
                    securityKeys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
                }
                else if (jwtCertificate.GetRSAPublicKey() is { } rsaPublicKey)
                {
                    keysToDispose.Add(rsaPublicKey);
                    var parameters = rsaPublicKey.ExportParameters(false);
                    securityKeys.Add(new RsaSecurityKey(parameters));
                }
                else
                {
                    return Result<MetadataBLOBPayloadJSON>.Fail();
                }
            }

            var isJwtCertificateValid = X509TrustChainValidator.IsFidoMetadataBlobJwtChainValid(
                rootCertificates.ToArray(),
                jwtCertificates.ToArray(),
                Options.CurrentValue.X509ChainValidation.OnValidateFidoMetadataBlobJwtChain);
            if (!isJwtCertificateValid)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            var jwtValidationResult = await JwtValidator.ValidateAsync(rawMetadata, securityKeys, cancellationToken);
            if (!jwtValidationResult.IsValid)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            if (!Base64Url.TryDecode(jwt.EncodedPayload, out var jwtPayloadBytes))
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            var payload = Encoding.UTF8.GetString(jwtPayloadBytes);
            var blobPayloadResult = SafeJsonSerializer.DeserializeNonNullable<MetadataBLOBPayloadJSON>(payload);
            if (blobPayloadResult.HasError)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            return Result<MetadataBLOBPayloadJSON>.Success(blobPayloadResult.Ok);
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

    protected virtual bool TryGetRawCertificates(JsonWebToken jwt, [NotNullWhen(true)] out byte[][]? rawCertificates)
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

    protected virtual byte[][] GetFidoMetadataRootCertificates()
    {
        return FidoMetadataRoots.GlobalSign;
    }
}
