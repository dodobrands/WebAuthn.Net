using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WebAuthn.Net.Demo.FidoConformance.Services.ConformanceMetadata;

/// <summary>
///     Checks the revocation status of the certificates of the FIDO Metadata Service blob signing chain against the CRLs published in their CRL distribution points.
/// </summary>
/// <remarks>
///     <para>
///         The MDS3 test server of the FIDO Conformance Tools signs the test blobs with certificates whose revocation information is published only as CRLs and only over HTTPS,
///         and one of the test blobs is signed by a revoked certificate, so the revocation status must be known to pass the tests.
///         The .NET <see cref="X509Chain" /> engine on macOS doesn't download CRLs at all (Apple's trust engine supports OCSP only), and on Linux it downloads CRLs only from <c>http://</c> URLs,
///         therefore every test blob is rejected there with <see cref="X509ChainStatusFlags.RevocationStatusUnknown" />.
///     </para>
///     <para>
///         This checker downloads the CRLs itself (following redirects), verifies their signatures with the issuer certificates from the chain and rejects the chain if any certificate
///         (except the trust anchor) is revoked or its CRL can't be obtained. It is used together with <see cref="X509RevocationMode.NoCheck" /> for the blob signing chain.
///     </para>
/// </remarks>
public class ConformanceCrlRevocationChecker
{
    /// <summary>
    ///     The name of the <see cref="HttpClient" /> used for downloading the CRLs.
    /// </summary>
    public const string HttpClientName = "ConformanceCrl";

    private const string CrlDistributionPointsOid = "2.5.29.31";
    private static readonly TimeSpan MaxCacheLifetime = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<Uri, CachedCrl> _cache = new();
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ConformanceCrlRevocationChecker> _logger;

    public ConformanceCrlRevocationChecker(IHttpClientFactory httpClientFactory, ILogger<ConformanceCrlRevocationChecker> logger)
    {
        ArgumentNullException.ThrowIfNull(httpClientFactory);
        ArgumentNullException.ThrowIfNull(logger);
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <summary>
    ///     Configures the <see cref="X509Chain" /> used for validating the FIDO Metadata Service blob signing chain: the same policy as the library default,
    ///     except that the revocation is not checked by the chain engine, because it is checked by <see cref="IsChainNotRevokedAsync" />.
    /// </summary>
    /// <param name="chain">The chain to configure.</param>
    public static void ConfigureFidoMetadataBlobJwtChain(X509Chain chain)
    {
        ArgumentNullException.ThrowIfNull(chain);
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    }

    /// <summary>
    ///     Checks that none of the certificates of the chain (except the trust anchor) is revoked according to the CRLs published in their CRL distribution points.
    /// </summary>
    /// <param name="chain">The successfully built chain.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns><see langword="true" /> if every certificate is known to be not revoked, otherwise (a certificate is revoked or its revocation status can't be determined) - <see langword="false" />.</returns>
    public async Task<bool> IsChainNotRevokedAsync(X509Chain chain, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chain);
        var elements = chain.ChainElements;
        // The last element is the trust anchor (the self-signed root from the custom trust store), which can't be meaningfully checked against a CRL it issued itself.
        for (var i = 0; i < elements.Count - 1; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var certificate = elements[i].Certificate;
            var issuer = elements[i + 1].Certificate;
            if (!await IsCertificateNotRevokedAsync(certificate, issuer, cancellationToken))
            {
                return false;
            }
        }

        return true;
    }

    private async Task<bool> IsCertificateNotRevokedAsync(X509Certificate2 certificate, X509Certificate2 issuer, CancellationToken cancellationToken)
    {
        var serialNumber = Convert.ToHexString(certificate.SerialNumberBytes.Span);
        var distributionPoints = GetCrlDistributionPointUrls(certificate);
        if (distributionPoints.Count == 0)
        {
            _logger.WarnNoCrlDistributionPoints(certificate.Subject, serialNumber);
            return false;
        }

        var now = DateTimeOffset.UtcNow;
        foreach (var distributionPoint in distributionPoints)
        {
            var crl = await GetCrlAsync(distributionPoint, issuer, now, cancellationToken);
            if (crl is null)
            {
                continue;
            }

            if (crl.IsRevoked(certificate.SerialNumberBytes.Span))
            {
                _logger.WarnCertificateRevoked(certificate.Subject, serialNumber, distributionPoint);
                return false;
            }

            _logger.DebugCertificateNotRevoked(certificate.Subject, serialNumber, distributionPoint);
            return true;
        }

        _logger.WarnRevocationStatusUnknown(certificate.Subject, serialNumber);
        return false;
    }

    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "A CRL that can't be downloaded or parsed is reported as an unknown revocation status")]
    private async Task<CachedCrl?> GetCrlAsync(Uri distributionPoint, X509Certificate2 issuer, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (_cache.TryGetValue(distributionPoint, out var cached) && cached.ExpiresAt > now)
        {
            return cached;
        }

        byte[] rawCrl;
        try
        {
            using var httpClient = _httpClientFactory.CreateClient(HttpClientName);
            rawCrl = await httpClient.GetByteArrayAsync(distributionPoint, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.WarnCrlDownloadFailed(exception, distributionPoint);
            return null;
        }

        ParsedCrl parsedCrl;
        try
        {
            parsedCrl = ParsedCrl.Parse(rawCrl);
        }
        catch (Exception exception)
        {
            _logger.WarnCrlInvalid(exception, distributionPoint);
            return null;
        }

        if (!parsedCrl.Issuer.Span.SequenceEqual(issuer.SubjectName.RawData))
        {
            _logger.WarnCrlIssuerMismatch(distributionPoint, issuer.Subject);
            return null;
        }

        if (!parsedCrl.VerifySignature(issuer))
        {
            _logger.WarnCrlSignatureInvalid(distributionPoint, issuer.Subject);
            return null;
        }

        if (parsedCrl.ThisUpdate > now || (parsedCrl.NextUpdate.HasValue && parsedCrl.NextUpdate.Value < now))
        {
            _logger.WarnCrlNotValidNow(distributionPoint, parsedCrl.ThisUpdate, parsedCrl.NextUpdate, now);
            return null;
        }

        var expiresAt = now.Add(MaxCacheLifetime);
        if (parsedCrl.NextUpdate.HasValue && parsedCrl.NextUpdate.Value < expiresAt)
        {
            expiresAt = parsedCrl.NextUpdate.Value;
        }

        var result = new CachedCrl(parsedCrl, expiresAt);
        _cache[distributionPoint] = result;
        _logger.DebugCrlDownloaded(distributionPoint, parsedCrl.RevokedSerialNumbers.Count, parsedCrl.ThisUpdate, parsedCrl.NextUpdate);
        return result;
    }

    // RFC 5280, 4.2.1.13:
    // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
    // DistributionPoint ::= SEQUENCE {
    //     distributionPoint [0] DistributionPointName OPTIONAL,
    //     reasons           [1] ReasonFlags OPTIONAL,
    //     cRLIssuer         [2] GeneralNames OPTIONAL }
    // DistributionPointName ::= CHOICE {
    //     fullName                [0] GeneralNames,
    //     nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
    // GeneralName ::= CHOICE { ..., uniformResourceIdentifier [6] IA5String, ... }
    // The module uses IMPLICIT tags, but a tag on a CHOICE (distributionPoint [0]) is always explicit.
    private static List<Uri> GetCrlDistributionPointUrls(X509Certificate2 certificate)
    {
        var result = new List<Uri>();
        var contextSpecific0 = new Asn1Tag(TagClass.ContextSpecific, 0);
        var uriTag = new Asn1Tag(TagClass.ContextSpecific, 6);
        foreach (var extension in certificate.Extensions)
        {
            if (!string.Equals(extension.Oid?.Value, CrlDistributionPointsOid, StringComparison.Ordinal))
            {
                continue;
            }

            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            var distributionPoints = reader.ReadSequence();
            while (distributionPoints.HasData)
            {
                var distributionPoint = distributionPoints.ReadSequence();
                if (!distributionPoint.HasData || !distributionPoint.PeekTag().HasSameClassAndValue(contextSpecific0))
                {
                    continue;
                }

                var distributionPointName = distributionPoint.ReadSequence(contextSpecific0);
                if (!distributionPointName.HasData || !distributionPointName.PeekTag().HasSameClassAndValue(contextSpecific0))
                {
                    continue;
                }

                var generalNames = distributionPointName.ReadSequence(contextSpecific0);
                while (generalNames.HasData)
                {
                    if (!generalNames.PeekTag().HasSameClassAndValue(uriTag))
                    {
                        generalNames.ReadEncodedValue();
                        continue;
                    }

                    var uriString = generalNames.ReadCharacterString(UniversalTagNumber.IA5String, uriTag);
                    if (Uri.TryCreate(uriString, UriKind.Absolute, out var uri)
                        && (string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) || string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
                    {
                        result.Add(uri);
                    }
                }
            }
        }

        return result;
    }

    private sealed class CachedCrl
    {
        private readonly ParsedCrl _crl;

        public CachedCrl(ParsedCrl crl, DateTimeOffset expiresAt)
        {
            _crl = crl;
            ExpiresAt = expiresAt;
        }

        public DateTimeOffset ExpiresAt { get; }

        public bool IsRevoked(ReadOnlySpan<byte> serialNumber)
        {
            return _crl.IsRevoked(serialNumber);
        }
    }

    // RFC 5280, 5.1:
    // CertificateList ::= SEQUENCE {
    //     tbsCertList        TBSCertList,
    //     signatureAlgorithm AlgorithmIdentifier,
    //     signatureValue     BIT STRING }
    // TBSCertList ::= SEQUENCE {
    //     version             Version OPTIONAL,
    //     signature           AlgorithmIdentifier,
    //     issuer              Name,
    //     thisUpdate          Time,
    //     nextUpdate          Time OPTIONAL,
    //     revokedCertificates SEQUENCE OF SEQUENCE {
    //         userCertificate    CertificateSerialNumber,
    //         revocationDate     Time,
    //         crlEntryExtensions Extensions OPTIONAL } OPTIONAL,
    //     crlExtensions       [0] EXPLICIT Extensions OPTIONAL }
    private sealed class ParsedCrl
    {
        private ParsedCrl(
            ReadOnlyMemory<byte> tbsCertList,
            string signatureAlgorithmOid,
            ReadOnlyMemory<byte> signature,
            ReadOnlyMemory<byte> issuer,
            DateTimeOffset thisUpdate,
            DateTimeOffset? nextUpdate,
            IReadOnlyCollection<BigInteger> revokedSerialNumbers)
        {
            TbsCertList = tbsCertList;
            SignatureAlgorithmOid = signatureAlgorithmOid;
            Signature = signature;
            Issuer = issuer;
            ThisUpdate = thisUpdate;
            NextUpdate = nextUpdate;
            RevokedSerialNumbers = revokedSerialNumbers;
        }

        public ReadOnlyMemory<byte> TbsCertList { get; }

        public string SignatureAlgorithmOid { get; }

        public ReadOnlyMemory<byte> Signature { get; }

        public ReadOnlyMemory<byte> Issuer { get; }

        public DateTimeOffset ThisUpdate { get; }

        public DateTimeOffset? NextUpdate { get; }

        public IReadOnlyCollection<BigInteger> RevokedSerialNumbers { get; }

        public static ParsedCrl Parse(byte[] rawCrl)
        {
            var reader = new AsnReader(rawCrl, AsnEncodingRules.DER);
            var certificateList = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            var tbsCertListEncoded = certificateList.PeekEncodedValue();
            var tbsCertList = certificateList.ReadSequence();
            var signatureAlgorithm = certificateList.ReadSequence();
            var signatureAlgorithmOid = signatureAlgorithm.ReadObjectIdentifier();
            var signature = certificateList.ReadBitString(out _);
            certificateList.ThrowIfNotEmpty();

            if (tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Integer))
            {
                tbsCertList.ReadInteger();
            }

            tbsCertList.ReadSequence();
            var issuer = tbsCertList.PeekEncodedValue();
            tbsCertList.ReadEncodedValue();
            var thisUpdate = ReadTime(tbsCertList);
            DateTimeOffset? nextUpdate = null;
            if (tbsCertList.HasData && IsTime(tbsCertList.PeekTag()))
            {
                nextUpdate = ReadTime(tbsCertList);
            }

            var revokedSerialNumbers = new List<BigInteger>();
            if (tbsCertList.HasData && tbsCertList.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var revokedCertificates = tbsCertList.ReadSequence();
                while (revokedCertificates.HasData)
                {
                    var revokedCertificate = revokedCertificates.ReadSequence();
                    revokedSerialNumbers.Add(revokedCertificate.ReadInteger());
                }
            }

            return new(
                tbsCertListEncoded,
                signatureAlgorithmOid,
                signature,
                issuer,
                thisUpdate,
                nextUpdate,
                revokedSerialNumbers);
        }

        public bool IsRevoked(ReadOnlySpan<byte> serialNumber)
        {
            var serial = new BigInteger(serialNumber, isUnsigned: false, isBigEndian: true);
            foreach (var revokedSerialNumber in RevokedSerialNumbers)
            {
                if (revokedSerialNumber == serial)
                {
                    return true;
                }
            }

            return false;
        }

        public bool VerifySignature(X509Certificate2 issuer)
        {
            switch (SignatureAlgorithmOid)
            {
                case "1.2.840.10045.4.3.2":
                    return VerifyEcdsa(issuer, HashAlgorithmName.SHA256);
                case "1.2.840.10045.4.3.3":
                    return VerifyEcdsa(issuer, HashAlgorithmName.SHA384);
                case "1.2.840.10045.4.3.4":
                    return VerifyEcdsa(issuer, HashAlgorithmName.SHA512);
                case "1.2.840.113549.1.1.11":
                    return VerifyRsa(issuer, HashAlgorithmName.SHA256);
                case "1.2.840.113549.1.1.12":
                    return VerifyRsa(issuer, HashAlgorithmName.SHA384);
                case "1.2.840.113549.1.1.13":
                    return VerifyRsa(issuer, HashAlgorithmName.SHA512);
                default:
                    return false;
            }
        }

        private bool VerifyEcdsa(X509Certificate2 issuer, HashAlgorithmName hashAlgorithm)
        {
            using var ecdsa = issuer.GetECDsaPublicKey();
            return ecdsa is not null && ecdsa.VerifyData(TbsCertList.Span, Signature.Span, hashAlgorithm, DSASignatureFormat.Rfc3279DerSequence);
        }

        private bool VerifyRsa(X509Certificate2 issuer, HashAlgorithmName hashAlgorithm)
        {
            using var rsa = issuer.GetRSAPublicKey();
            return rsa is not null && rsa.VerifyData(TbsCertList.Span, Signature.Span, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }

        private static bool IsTime(Asn1Tag tag)
        {
            return tag.HasSameClassAndValue(Asn1Tag.UtcTime) || tag.HasSameClassAndValue(Asn1Tag.GeneralizedTime);
        }

        private static DateTimeOffset ReadTime(AsnReader reader)
        {
            return reader.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime)
                ? reader.ReadUtcTime()
                : reader.ReadGeneralizedTime();
        }
    }
}

/// <summary>
///     Extension methods for logging the CRL revocation checks.
/// </summary>
public static partial class ConformanceCrlRevocationCheckerLoggingExtensions
{
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The certificate '{Subject}' (serial number {SerialNumber}) of the FIDO Metadata Service blob signing chain has no CRL distribution points, so its revocation status can't be determined")]
    public static partial void WarnNoCrlDistributionPoints(this ILogger logger, string subject, string serialNumber);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The certificate '{Subject}' (serial number {SerialNumber}) of the FIDO Metadata Service blob signing chain is revoked according to the CRL {DistributionPoint}")]
    public static partial void WarnCertificateRevoked(this ILogger logger, string subject, string serialNumber, Uri distributionPoint);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The revocation status of the certificate '{Subject}' (serial number {SerialNumber}) of the FIDO Metadata Service blob signing chain can't be determined because none of its CRLs could be obtained")]
    public static partial void WarnRevocationStatusUnknown(this ILogger logger, string subject, string serialNumber);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CRL {DistributionPoint} can't be downloaded")]
    public static partial void WarnCrlDownloadFailed(this ILogger logger, Exception exception, Uri distributionPoint);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CRL {DistributionPoint} can't be parsed")]
    public static partial void WarnCrlInvalid(this ILogger logger, Exception exception, Uri distributionPoint);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CRL {DistributionPoint} was not issued by the expected issuer '{Issuer}'")]
    public static partial void WarnCrlIssuerMismatch(this ILogger logger, Uri distributionPoint, string issuer);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The signature of the CRL {DistributionPoint} can't be verified with the public key of '{Issuer}'")]
    public static partial void WarnCrlSignatureInvalid(this ILogger logger, Uri distributionPoint, string issuer);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The CRL {DistributionPoint} is not valid at the current time {Now:O}: thisUpdate = {ThisUpdate:O}, nextUpdate = {NextUpdate:O}")]
    public static partial void WarnCrlNotValidNow(this ILogger logger, Uri distributionPoint, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate, DateTimeOffset now);

    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "The CRL {DistributionPoint} with {RevokedCount} revoked certificates was downloaded and verified: thisUpdate = {ThisUpdate:O}, nextUpdate = {NextUpdate:O}")]
    public static partial void DebugCrlDownloaded(this ILogger logger, Uri distributionPoint, int revokedCount, DateTimeOffset thisUpdate, DateTimeOffset? nextUpdate);

    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "The certificate '{Subject}' (serial number {SerialNumber}) of the FIDO Metadata Service blob signing chain is not revoked according to the CRL {DistributionPoint}")]
    public static partial void DebugCertificateNotRevoked(this ILogger logger, string subject, string serialNumber, Uri distributionPoint);
}
