using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultFidoMetadataProvider : IFidoMetadataProvider
{
    public DefaultFidoMetadataProvider(IFidoMetadataHttpClient metadataHttpClient, ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(metadataHttpClient);
        ArgumentNullException.ThrowIfNull(timeProvider);
        MetadataHttpClient = metadataHttpClient;
        TimeProvider = timeProvider;
    }

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

            var isJwtCertificateValid = X509TrustChainValidator.IsValidCertificateChain(rootCertificates.ToArray(), jwtCertificates.ToArray());
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
            var blobPayload = JsonSerializer.Deserialize<MetadataBLOBPayloadJSON>(payload);
            if (blobPayload is null)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            return Result<MetadataBLOBPayloadJSON>.Success(blobPayload);
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

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract")]
    protected virtual bool TryGetRawCertificates(JsonWebToken jwt, [NotNullWhen(true)] out byte[][]? rawCertificates)
    {
        if (jwt is null)
        {
            rawCertificates = null;
            return false;
        }

        var header = JwtHeader.Base64UrlDeserialize(jwt.EncodedHeader);
        if (!header.TryGetValue("x5c", out var certificatesObject) || certificatesObject is null)
        {
            rawCertificates = null;
            return false;
        }

        if (certificatesObject is string certificatesString)
        {
            if (!Base64Raw.TryDecode(certificatesString, out var rawCert))
            {
                rawCertificates = null;
                return false;
            }

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

                if (!Base64Raw.TryDecode(certificateString, out var rawCert))
                {
                    rawCertificates = null;
                    return false;
                }

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

    protected virtual byte[][] GetFidoMetadataRootCertificates()
    {
        return FidoMetadataRoots.GlobalSign;
    }
}
