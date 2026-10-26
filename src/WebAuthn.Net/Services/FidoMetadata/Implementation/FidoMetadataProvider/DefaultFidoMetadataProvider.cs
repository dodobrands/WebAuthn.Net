using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebAuthn.Net.Configuration.Options;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider.Constants;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataProvider;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataProvider" />.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultFidoMetadataProvider : IFidoMetadataProvider
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataProvider" />.
    /// </summary>
    /// <param name="options">Accessor for getting the current value of global options.</param>
    /// <param name="safeJsonSerializer">Safe (exceptionless) JSON serializer.</param>
    /// <param name="metadataHttpClient">An HTTP client for retrieving blob with metadata from the FIDO Metadata Service.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="counters">Counters for FIDO Metadata Service metrics, used to count the downloads and the reasons why a blob is not provided.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataProvider(
        IOptionsMonitor<WebAuthnOptions> options,
        ISafeJsonSerializer safeJsonSerializer,
        IFidoMetadataHttpClient metadataHttpClient,
        ITimeProvider timeProvider,
        IFidoMetadataCounters counters,
        ILogger<DefaultFidoMetadataProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(safeJsonSerializer);
        ArgumentNullException.ThrowIfNull(metadataHttpClient);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Options = options;
        SafeJsonSerializer = safeJsonSerializer;
        MetadataHttpClient = metadataHttpClient;
        TimeProvider = timeProvider;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Accessor for getting the current value of global options.
    /// </summary>
    protected IOptionsMonitor<WebAuthnOptions> Options { get; }

    /// <summary>
    ///     Safe (exceptionless) JSON serializer.
    /// </summary>
    protected ISafeJsonSerializer SafeJsonSerializer { get; }

    /// <summary>
    ///     An HTTP client for retrieving blob with metadata from the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataHttpClient MetadataHttpClient { get; }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Counters for FIDO Metadata Service metrics, used to count the downloads and the reasons why a blob is not provided (see <see cref="FidoMetadataDownloadFailures" />).
    /// </summary>
    protected IFidoMetadataCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultFidoMetadataProvider> Logger { get; }

    /// <inheritdoc />
    /// <remarks>
    ///     Every reason for which the blob is rejected is logged at the <see cref="LogLevel.Warning" /> level and counted (see <see cref="FidoMetadataDownloadFailures" />),
    ///     because a silently rejected blob would leave the FIDO metadata stale without any visible cause.
    /// </remarks>
    public virtual async Task<Result<MetadataBLOBPayloadJSON>> DownloadMetadataAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Counters.IncrementDownloadStart();
        string rawMetadata;
        try
        {
            rawMetadata = await MetadataHttpClient.DownloadMetadataAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TimeoutException or IOException)
        {
            // The request failed, the response has an unsuccessful status code or exceeds the limits of the client, or the connection was broken.
            // A failed download is an expected failure rather than an exception: it is reported and counted with its reason, and the blob is rejected
            // (the background ingestion retries the download later).
            Logger.WarnDownloadFailed(exception);
            return FailDownload(exception is TimeoutException
                ? FidoMetadataDownloadFailures.Timeout
                : FidoMetadataDownloadFailures.RequestFailed);
        }

        var result = await ValidateBlobAsync(rawMetadata, false, FailDownload, cancellationToken);
        if (result.HasError)
        {
            return result;
        }

        Logger.DebugMetadataDownloaded(result.Ok.No, result.Ok.Entries?.Length ?? 0);
        Counters.IncrementDownloadEnd(true);
        return result;
    }

    /// <inheritdoc />
    /// <remarks>
    ///     <para>
    ///         The blob is validated the same way as a blob downloaded from the FIDO Metadata Service: its signature and its certificate chain up to the root certificates of the FIDO Metadata Service
    ///         embedded in the library (<see cref="GetEmbeddedFidoRootCertificates" />). The only difference is that the chain is validated according to
    ///         <see cref="X509ChainValidationOptions.OnValidateEmbeddedFidoMetadataBlobJwtChain" />, which by default doesn't check the validity period and the revocation status of the signing certificates,
    ///         and without the additional validation (<see cref="ValidateJwtCertificateChainAsync" />), so that the blob embedded in the application can be used regardless of the time and of the availability of the network.
    ///     </para>
    ///     <para>
    ///         Every reason for which the blob is not provided is logged at the <see cref="LogLevel.Warning" /> level and counted (see <see cref="FidoMetadataEmbeddedBlobFailures" />).
    ///     </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="assembly" /> or <paramref name="resourceName" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="resourceName" /> is empty</exception>
    public virtual async Task<Result<MetadataBLOBPayloadJSON>> LoadEmbeddedMetadataAsync(Assembly assembly, string resourceName, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrEmpty(resourceName);
        cancellationToken.ThrowIfCancellationRequested();
        Counters.IncrementEmbeddedLoadStart();
        var assemblyName = assembly.FullName;
        string rawMetadata;
        await using (var resourceStream = assembly.GetManifestResourceStream(resourceName))
        {
            if (resourceStream is null)
            {
                Logger.WarnEmbeddedBlobResourceNotFound(resourceName, assemblyName, FormatManifestResourceNames(assembly));
                return FailEmbeddedLoad(FidoMetadataEmbeddedBlobFailures.ResourceNotFound);
            }

            using var reader = new StreamReader(resourceStream, Encoding.UTF8, true);
            // Not calling Trim can potentially break JWT validation (for example, the file of the blob may end with a line break).
            rawMetadata = (await reader.ReadToEndAsync(cancellationToken)).Trim();
        }

        var result = await ValidateBlobAsync(
            rawMetadata,
            true,
            reason =>
            {
                // The warnings of the validation describe the reason, but not the blob: this one tells that it is the blob embedded in the application.
                Logger.WarnEmbeddedBlobRejected(resourceName, assemblyName, reason);
                return FailEmbeddedLoad(reason);
            },
            cancellationToken);
        if (result.HasError)
        {
            return result;
        }

        Logger.DebugEmbeddedMetadataLoaded(result.Ok.No, result.Ok.Entries?.Length ?? 0, resourceName, assemblyName);
        Counters.IncrementEmbeddedLoadEnd(true);
        return result;
    }

    // Validates the signature of the blob, its certificate chain and its payload. Every reason for which the blob is rejected is logged and reported through 'fail', which counts it.
    // The blob embedded in the application (isEmbedded) is validated regardless of the validity period of its certificates and without the additional validation of the chain,
    // see X509ChainValidationOptions.OnValidateEmbeddedFidoMetadataBlobJwtChain.
    private async Task<Result<MetadataBLOBPayloadJSON>> ValidateBlobAsync(
        string rawMetadata,
        bool isEmbedded,
        Func<string, Result<MetadataBLOBPayloadJSON>> fail,
        CancellationToken cancellationToken)
    {
        var certificatesToDispose = new List<X509Certificate2>();
        var keysToDispose = new List<AsymmetricAlgorithm>();
        try
        {
            JsonWebToken jwt;
            try
            {
                jwt = new(rawMetadata);
            }
            catch (ArgumentException exception)
            {
                // The data is not a JWS in the compact serialization (for example, an error page returned with a successful status code, or a wrong file embedded in the application).
                Logger.WarnJwtMalformed(exception);
                return fail(FidoMetadataDownloadFailures.JwtMalformed);
            }

            if (!TryGetRawCertificates(jwt, out var headerCertificates) || headerCertificates.Length == 0)
            {
                Logger.WarnJwtHeaderCertificatesMissing();
                return fail(FidoMetadataDownloadFailures.X5CInvalid);
            }

            var currentDate = TimeProvider.GetPreciseUtcDateTime();
            var jwtCertificates = new List<X509Certificate2>();
            for (var i = 0; i < headerCertificates.Length; i++)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(headerCertificates[i], out var jwtCertificate))
                {
                    jwtCertificate?.Dispose();
                    Logger.WarnJwtHeaderCertificateInvalid(i);
                    return fail(FidoMetadataDownloadFailures.X5CInvalid);
                }

                certificatesToDispose.Add(jwtCertificate);
                jwtCertificates.Add(jwtCertificate);
                if (!isEmbedded && (currentDate < jwtCertificate.NotBefore || currentDate > jwtCertificate.NotAfter))
                {
                    Logger.WarnJwtHeaderCertificateNotValidNow(
                        i,
                        jwtCertificate.Subject,
                        jwtCertificate.NotBefore.ToUniversalTime(),
                        jwtCertificate.NotAfter.ToUniversalTime(),
                        currentDate);
                    return fail(FidoMetadataDownloadFailures.X5CInvalid);
                }
            }

            // build root certificates chain that avoid expired certificates (the chain of the embedded blob is validated regardless of the validity period)
            var fidoRootCertificates = GetEmbeddedFidoRootCertificates();
            if (fidoRootCertificates.Count == 0)
            {
                Logger.WarnRootCertificatesMissing();
                return fail(FidoMetadataDownloadFailures.RootCertificatesInvalid);
            }

            var rootCertificates = new List<X509Certificate2>();
            var rootCertificateIndex = 0;
            foreach (var fidoRootCertBytes in fidoRootCertificates)
            {
                if (!X509CertificateInMemoryLoader.TryLoad(fidoRootCertBytes, out var fidoRootCertificate))
                {
                    fidoRootCertificate?.Dispose();
                    Logger.WarnRootCertificateInvalid(rootCertificateIndex);
                    return fail(FidoMetadataDownloadFailures.RootCertificatesInvalid);
                }

                certificatesToDispose.Add(fidoRootCertificate);
                if (isEmbedded || (currentDate >= fidoRootCertificate.NotBefore && currentDate <= fidoRootCertificate.NotAfter))
                {
                    rootCertificates.Add(fidoRootCertificate);
                }

                rootCertificateIndex++;
            }

            if (rootCertificates.Count == 0)
            {
                Logger.WarnRootCertificatesNotValidNow(fidoRootCertificates.Count, currentDate);
                return fail(FidoMetadataDownloadFailures.RootCertificatesInvalid);
            }

            // https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
            // The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
            // Only the chain of the first certificate is validated (the other certificates merely help to build it), so the signature is validated with its key alone:
            // accepting the key of any certificate from 'x5c' would let anyone who can serve a blob (a proxy, a mirror, a man in the middle) append their own certificate to the genuine chain and sign the blob.
            var signingCertificate = jwtCertificates[0];
            SecurityKey signingKey;
            if (signingCertificate.GetECDsaPublicKey() is { } ecdsaPublicKey)
            {
                keysToDispose.Add(ecdsaPublicKey);
                signingKey = new ECDsaSecurityKey(ecdsaPublicKey);
            }
            else if (signingCertificate.GetRSAPublicKey() is { } rsaPublicKey)
            {
                keysToDispose.Add(rsaPublicKey);
                var parameters = rsaPublicKey.ExportParameters(false);
                signingKey = new RsaSecurityKey(parameters);
            }
            else
            {
                Logger.WarnJwtHeaderCertificateUnsupportedPublicKey(signingCertificate.Subject);
                return fail(FidoMetadataDownloadFailures.X5CInvalid);
            }

            X509Chain? jwtCertificateChain = null;
            try
            {
                var chainValidationOptions = Options.CurrentValue.X509ChainValidation;
                if (!X509TrustChainValidator.TryBuildFidoMetadataBlobJwtChain(
                        rootCertificates.ToArray(),
                        jwtCertificates.ToArray(),
                        isEmbedded
                            ? chainValidationOptions.OnValidateEmbeddedFidoMetadataBlobJwtChain
                            : chainValidationOptions.OnValidateFidoMetadataBlobJwtChain,
                        out jwtCertificateChain,
                        out var chainStatus))
                {
                    Logger.WarnJwtCertificateChainInvalid(FormatChainStatus(chainStatus));
                    return fail(FidoMetadataDownloadFailures.ChainInvalid);
                }

                if (!isEmbedded && !await ValidateJwtCertificateChainAsync(jwtCertificateChain, cancellationToken))
                {
                    Logger.WarnJwtCertificateChainRejected();
                    return fail(FidoMetadataDownloadFailures.ChainRejected);
                }
            }
            finally
            {
                jwtCertificateChain?.Dispose();
            }

            var jwtValidationResult = await JwtValidator.ValidateAsync(rawMetadata, new[] { signingKey }, cancellationToken);
            if (!jwtValidationResult.IsValid)
            {
                Logger.WarnJwtSignatureInvalid(jwtValidationResult.Exception);
                return fail(FidoMetadataDownloadFailures.SignatureInvalid);
            }

            if (!Base64Url.TryDecode(jwt.EncodedPayload, out var jwtPayloadBytes))
            {
                Logger.WarnJwtPayloadNotBase64Url();
                return fail(FidoMetadataDownloadFailures.PayloadInvalid);
            }

            var payload = Encoding.UTF8.GetString(jwtPayloadBytes);
            var blobPayloadResult = SafeJsonSerializer.DeserializeNonNullable<MetadataBLOBPayloadJSON>(payload);
            if (blobPayloadResult.HasError)
            {
                Logger.WarnJwtPayloadDeserializationFailed();
                return fail(FidoMetadataDownloadFailures.PayloadInvalid);
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

    // the blob is not provided: the reason (one of FidoMetadataDownloadFailures) and the unsuccessful completion are counted
    private Result<MetadataBLOBPayloadJSON> FailDownload(string reason)
    {
        Counters.IncrementDownloadFailure(reason);
        Counters.IncrementDownloadEnd(false);
        return Result<MetadataBLOBPayloadJSON>.Fail();
    }

    // the blob embedded in the application is not provided: the reason (one of FidoMetadataEmbeddedBlobFailures) and the unsuccessful completion are counted
    private Result<MetadataBLOBPayloadJSON> FailEmbeddedLoad(string reason)
    {
        Counters.IncrementEmbeddedLoadFailure(reason);
        Counters.IncrementEmbeddedLoadEnd(false);
        return Result<MetadataBLOBPayloadJSON>.Fail();
    }

    // The names of the manifest resources of the assembly, for the warning about a resource that is not found (the most common mistake is the name of the resource).
    private static string FormatManifestResourceNames(Assembly assembly)
    {
        const int maxNames = 16;
        var names = assembly.GetManifestResourceNames();
        if (names.Length == 0)
        {
            return "<none>";
        }

        var formattedNames = string.Join(", ", names.Order(StringComparer.Ordinal).Take(maxNames).Select(static x => $"'{x}'"));
        return names.Length > maxNames
            ? $"{formattedNames}, ... ({names.Length} in total)"
            : formattedNames;
    }

    /// <summary>
    ///     Performs additional validation of the successfully built signing certificate chain of the blob obtained from the FIDO Metadata Service.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         The default implementation accepts every chain, because the chain has already been validated according to
    ///         <see cref="X509ChainValidationOptions.OnValidateFidoMetadataBlobJwtChain" />.
    ///     </para>
    ///     <para>
    ///         Override this method to apply checks that the <see cref="X509Chain" /> engine of the platform can't perform itself, for example,
    ///         a revocation check against CRLs that the platform doesn't download (the .NET chain engine on macOS doesn't download CRLs at all,
    ///         and on Linux it downloads them only from <c>http://</c> URLs). In such a case, configure <see cref="X509ChainPolicy.RevocationMode" />
    ///         to <see cref="X509RevocationMode.NoCheck" /> in <see cref="X509ChainValidationOptions.OnValidateFidoMetadataBlobJwtChain" /> and check the revocation here.
    ///     </para>
    ///     <para>
    ///         The method is called only for the blobs downloaded from the FIDO Metadata Service. The chain of the blob embedded in the application is validated only according to
    ///         <see cref="X509ChainValidationOptions.OnValidateEmbeddedFidoMetadataBlobJwtChain" />, without the network.
    ///     </para>
    /// </remarks>
    /// <param name="chain">The successfully built signing certificate chain of the blob. The chain is disposed by the caller after this method completes.</param>
    /// <param name="cancellationToken">Cancellation token for an asynchronous operation.</param>
    /// <returns><see langword="true" /> if the chain is acceptable and the blob can be used, otherwise - <see langword="false" /> (the blob is rejected).</returns>
    protected virtual Task<bool> ValidateJwtCertificateChainAsync(X509Chain chain, CancellationToken cancellationToken)
    {
        return Task.FromResult(true);
    }

    /// <summary>
    ///     Formats the status of an X509 certificate chain for logging.
    /// </summary>
    /// <param name="chainStatus">The status of the chain.</param>
    /// <returns>A human-readable description of the chain status flags.</returns>
    protected static string FormatChainStatus(X509ChainStatus[] chainStatus)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (chainStatus is null || chainStatus.Length == 0)
        {
            return "<no chain status flags were reported>";
        }

        var result = new StringBuilder();
        foreach (var status in chainStatus)
        {
            if (result.Length > 0)
            {
                result.Append("; ");
            }

            result.Append(status.Status.ToString());
            var information = status.StatusInformation?.Trim();
            if (!string.IsNullOrEmpty(information))
            {
                result.Append(" (").Append(information).Append(')');
            }
        }

        return result.ToString();
    }

    /// <summary>
    ///     Returns X509v3 certificates from the JWS (JWT) token header of a blob obtained from the FIDO Metadata Service.
    /// </summary>
    /// <param name="jwt">JWS (JWT) token of a blob obtained from the FIDO Metadata Service.</param>
    /// <param name="rawCertificates">Output parameter. If the method returns <see langword="true" /> - contains X509v3 certificates in the order they appear in the JWS token header, if the method return <see langword="false" />, contains <see langword="null" />.</param>
    /// <returns>If the extraction of certificates from the header was successful, returns <see langword="true" />, otherwise, returns <see langword="false" />. </returns>
    // ReSharper disable once VirtualMemberNeverOverridden.Global
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

    /// <summary>
    ///     Returns a collection of FIDO root certificates embedded in the library for validating certificate chains that sign the blobs obtained from the FIDO Metadata Service.
    /// </summary>
    /// <returns>An instance of <see cref="UniqueByteArraysCollection" />. It may return an empty collection, but it never returns <see langword="null" />.</returns>
    protected virtual UniqueByteArraysCollection GetEmbeddedFidoRootCertificates()
    {
        return new(FidoMetadataRoots.GlobalSign);
    }
}

/// <summary>
///     Extension methods for logging the retrieval of the FIDO Metadata Service blob.
/// </summary>
public static partial class DefaultFidoMetadataProviderLoggingExtensions
{
    /// <summary>
    ///     The FIDO Metadata Service blob can't be downloaded
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception describing why the download failed.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service blob can't be downloaded")]
    public static partial void WarnDownloadFailed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The downloaded FIDO Metadata Service blob is not a JWS (JWT) in the compact serialization
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception describing why the downloaded data can't be parsed as a JWS (JWT).</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The downloaded FIDO Metadata Service blob is not a JWS (JWT) in the compact serialization")]
    public static partial void WarnJwtMalformed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The JWT header of the FIDO Metadata Service blob doesn't contain a valid 'x5c' member with the signing certificates
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The JWT header of the FIDO Metadata Service blob doesn't contain a valid 'x5c' member with the signing certificates")]
    public static partial void WarnJwtHeaderCertificatesMissing(this ILogger logger);

    /// <summary>
    ///     The certificate #{Index} from the 'x5c' member of the FIDO Metadata Service blob JWT header can't be loaded as an X509v3 certificate with an ECDSA or RSA public key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="index">The zero-based index of the certificate in the 'x5c' member.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The certificate #{Index} from the 'x5c' member of the FIDO Metadata Service blob JWT header can't be loaded as an X509v3 certificate with an ECDSA or RSA public key")]
    public static partial void WarnJwtHeaderCertificateInvalid(this ILogger logger, int index);

    /// <summary>
    ///     The certificate #{Index} ('{Subject}') from the 'x5c' member of the FIDO Metadata Service blob JWT header is not valid at the current time {Now}: its validity period is from {NotBefore} to {NotAfter}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="index">The zero-based index of the certificate in the 'x5c' member.</param>
    /// <param name="subject">The subject of the certificate.</param>
    /// <param name="notBefore">The start of the validity period of the certificate (UTC).</param>
    /// <param name="notAfter">The end of the validity period of the certificate (UTC).</param>
    /// <param name="now">The current time (UTC).</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The certificate #{Index} ('{Subject}') from the 'x5c' member of the FIDO Metadata Service blob JWT header is not valid at the current time {Now:O}: its validity period is from {NotBefore:O} to {NotAfter:O}")]
    public static partial void WarnJwtHeaderCertificateNotValidNow(this ILogger logger, int index, string subject, DateTime notBefore, DateTime notAfter, DateTimeOffset now);

    /// <summary>
    ///     There are no root certificates for validating the signing certificate chain of the FIDO Metadata Service blob
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "There are no root certificates for validating the signing certificate chain of the FIDO Metadata Service blob")]
    public static partial void WarnRootCertificatesMissing(this ILogger logger);

    /// <summary>
    ///     The root certificate #{Index} for validating the signing certificate chain of the FIDO Metadata Service blob can't be loaded as an X509v3 certificate with an ECDSA or RSA public key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="index">The zero-based index of the root certificate in the collection of root certificates.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The root certificate #{Index} for validating the signing certificate chain of the FIDO Metadata Service blob can't be loaded as an X509v3 certificate with an ECDSA or RSA public key")]
    public static partial void WarnRootCertificateInvalid(this ILogger logger, int index);

    /// <summary>
    ///     None of the {Total} root certificates for validating the signing certificate chain of the FIDO Metadata Service blob is valid at the current time {Now}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="total">The total number of root certificates.</param>
    /// <param name="now">The current time (UTC).</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "None of the {Total} root certificates for validating the signing certificate chain of the FIDO Metadata Service blob is valid at the current time {Now:O}")]
    public static partial void WarnRootCertificatesNotValidNow(this ILogger logger, int total, DateTimeOffset now);

    /// <summary>
    ///     The signing certificate '{Subject}' (the first certificate in the 'x5c' member of the FIDO Metadata Service blob JWT header) contains neither an ECDSA nor an RSA public key
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="subject">The subject of the certificate.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The signing certificate '{Subject}' (the first certificate in the 'x5c' member of the FIDO Metadata Service blob JWT header) contains neither an ECDSA nor an RSA public key")]
    public static partial void WarnJwtHeaderCertificateUnsupportedPublicKey(this ILogger logger, string subject);

    /// <summary>
    ///     The signing certificate chain of the FIDO Metadata Service blob is invalid: {ChainStatus}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="chainStatus">The description of the X509 chain status flags.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The signing certificate chain of the FIDO Metadata Service blob is invalid: {ChainStatus}")]
    public static partial void WarnJwtCertificateChainInvalid(this ILogger logger, string chainStatus);

    /// <summary>
    ///     The signing certificate chain of the FIDO Metadata Service blob was rejected by the additional validation
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The signing certificate chain of the FIDO Metadata Service blob was rejected by the additional validation")]
    public static partial void WarnJwtCertificateChainRejected(this ILogger logger);

    /// <summary>
    ///     The signature of the FIDO Metadata Service blob JWT is not valid for the key of the signing certificate (the first certificate in the 'x5c' member of the JWT header)
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception describing why the signature validation failed, if any.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The signature of the FIDO Metadata Service blob JWT is not valid for the key of the signing certificate (the first certificate in the 'x5c' member of the JWT header)")]
    public static partial void WarnJwtSignatureInvalid(this ILogger logger, Exception? exception);

    /// <summary>
    ///     The payload of the FIDO Metadata Service blob JWT is not a valid base64url string
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The payload of the FIDO Metadata Service blob JWT is not a valid base64url string")]
    public static partial void WarnJwtPayloadNotBase64Url(this ILogger logger);

    /// <summary>
    ///     The payload of the FIDO Metadata Service blob JWT can't be deserialized into MetadataBLOBPayloadJSON
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The payload of the FIDO Metadata Service blob JWT can't be deserialized into MetadataBLOBPayloadJSON")]
    public static partial void WarnJwtPayloadDeserializationFailed(this ILogger logger);

    /// <summary>
    ///     The FIDO Metadata Service blob (no: {No}) with {Entries} entries was downloaded and its signature was verified
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the blob.</param>
    /// <param name="entries">The number of entries in the blob.</param>
    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "The FIDO Metadata Service blob (no: {No}) with {Entries} entries was downloaded and its signature was verified")]
    public static partial void DebugMetadataDownloaded(this ILogger logger, long no, int entries);

    /// <summary>
    ///     The FIDO Metadata Service blob embedded in the application can't be loaded: the assembly '{Assembly}' doesn't contain the manifest resource '{ResourceName}' (the manifest resources of the assembly: {ResourceNames})
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="resourceName">The name of the manifest resource that is expected to contain the blob.</param>
    /// <param name="assembly">The full name of the assembly.</param>
    /// <param name="resourceNames">The names of the manifest resources that the assembly contains.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service blob embedded in the application can't be loaded: the assembly '{Assembly}' doesn't contain the manifest resource '{ResourceName}' (the manifest resources of the assembly: {ResourceNames})")]
    public static partial void WarnEmbeddedBlobResourceNotFound(this ILogger logger, string resourceName, string? assembly, string resourceNames);

    /// <summary>
    ///     The FIDO Metadata Service blob embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') was rejected: {Reason}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="resourceName">The name of the manifest resource that contains the blob.</param>
    /// <param name="assembly">The full name of the assembly.</param>
    /// <param name="reason">The reason why the blob was rejected (one of <see cref="FidoMetadataEmbeddedBlobFailures" />).</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service blob embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') was rejected: {Reason}")]
    public static partial void WarnEmbeddedBlobRejected(this ILogger logger, string resourceName, string? assembly, string reason);

    /// <summary>
    ///     The FIDO Metadata Service blob (no: {No}) with {Entries} entries embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') was loaded and its signature was verified
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the blob.</param>
    /// <param name="entries">The number of entries in the blob.</param>
    /// <param name="resourceName">The name of the manifest resource that contains the blob.</param>
    /// <param name="assembly">The full name of the assembly.</param>
    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "The FIDO Metadata Service blob (no: {No}) with {Entries} entries embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') was loaded and its signature was verified")]
    public static partial void DebugEmbeddedMetadataLoaded(this ILogger logger, long no, int entries, string resourceName, string? assembly);
}
