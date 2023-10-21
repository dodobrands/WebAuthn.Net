using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
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

        var jwtCertificates = new List<X509Certificate2>();
        var rootCertificates = new List<X509Certificate2>();
        var securityKeys = new List<SecurityKey>();
        try
        {
            var rawMetadata = await MetadataHttpClient.DownloadMetadataAsync(cancellationToken);
            var jwt = new JsonWebToken(rawMetadata);
            if (!TryGetRawCertificates(jwt, out var headerCertificates))
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            foreach (var certBytes in headerCertificates)
            {
                var cert = X509CertificateInMemoryLoader.Load(certBytes);
                jwtCertificates.Add(cert);
                if (currentDate < cert.NotBefore || currentDate > cert.NotAfter)
                {
                    return Result<MetadataBLOBPayloadJSON>.Fail();
                }
            }

            // build root certificates chain that avoid expired certificates
            var rootCertificatesToValidate = new List<X509Certificate2>();
            foreach (var fidoRootCertBytes in FidoMetadataRoots.GlobalSign)
            {
                var cert = X509CertificateInMemoryLoader.Load(fidoRootCertBytes);
                rootCertificates.Add(cert);
                if (currentDate >= cert.NotBefore && currentDate <= cert.NotAfter)
                {
                    rootCertificatesToValidate.Add(cert);
                }
            }

            foreach (var jwtCertificate in jwtCertificates)
            {
                if (jwtCertificate.GetECDsaPublicKey() is { } ecdsaPublicKey)
                {
                    securityKeys.Add(new ECDsaSecurityKey(ecdsaPublicKey));
                }
                else if (jwtCertificate.GetRSAPublicKey() is { } rsaPublicKey)
                {
                    securityKeys.Add(new RsaSecurityKey(rsaPublicKey));
                }
                else
                {
                    return Result<MetadataBLOBPayloadJSON>.Fail();
                }

                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                foreach (var rootCertificateToValidate in rootCertificatesToValidate)
                {
                    chain.ChainPolicy.CustomTrustStore.Add(rootCertificateToValidate);
                }

                var isValid = chain.Build(jwtCertificate);
                if (!isValid)
                {
                    return Result<MetadataBLOBPayloadJSON>.Fail();
                }
            }

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = securityKeys,
                ValidateLifetime = false,
                ValidateAudience = false,
                ValidateIssuer = false
            };
            var tokenHandler = new JwtSecurityTokenHandler
            {
                MaximumTokenSizeInBytes = rawMetadata.Length * 2
            };
            tokenHandler.InboundClaimFilter.Clear();
            tokenHandler.InboundClaimTypeMap.Clear();
            tokenHandler.OutboundAlgorithmMap.Clear();
            tokenHandler.OutboundClaimTypeMap.Clear();
            var validationResult = await tokenHandler.ValidateTokenAsync(rawMetadata, validationParameters);
            if (!validationResult.IsValid)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            var payload = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(jwt.EncodedPayload));
            var blobPayload = JsonSerializer.Deserialize<MetadataBLOBPayloadJSON>(payload);
            if (blobPayload is null)
            {
                return Result<MetadataBLOBPayloadJSON>.Fail();
            }

            return Result<MetadataBLOBPayloadJSON>.Success(blobPayload);
        }
        finally
        {
            foreach (var securityKey in securityKeys)
            {
                switch (securityKey)
                {
                    case ECDsaSecurityKey ecdsaKey:
                        {
                            ecdsaKey.ECDsa.Dispose();
                            break;
                        }
                    case RsaSecurityKey rsaKey:
                        {
                            rsaKey.Rsa.Dispose();
                            break;
                        }
                    case X509SecurityKey x509Key:
                        {
                            x509Key.Certificate.Dispose();
                            break;
                        }
                }
            }

            foreach (var certificate in jwtCertificates)
            {
                certificate.Dispose();
            }

            foreach (var rootCertificate in rootCertificates)
            {
                rootCertificate.Dispose();
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
}
