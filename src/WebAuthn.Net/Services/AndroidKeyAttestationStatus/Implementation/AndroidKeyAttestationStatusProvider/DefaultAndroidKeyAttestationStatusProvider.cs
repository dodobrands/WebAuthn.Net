using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusProvider.Constants;
using WebAuthn.Net.Services.AndroidKeyAttestationStatus.Models.Protocol.Json;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Services.AndroidKeyAttestationStatus.Implementation.AndroidKeyAttestationStatusProvider;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatusProvider" />.
/// </summary>
/// <remarks>
///     <para>
///         Google doesn't sign the status list, so it is used as it is, downloaded or embedded in the application. The provider only checks that it matches its
///         <a href="https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status">documented JSON format</a> (<see cref="AndroidKeyAttestationStatusListJSON" />):
///         an object with an 'entries' object whose values are objects with the documented members.
///     </para>
///     <para>
///         Every reason for which the status list is not provided is logged at the <see cref="LogLevel.Warning" /> level and counted
///         (see <see cref="AndroidKeyAttestationStatusDownloadFailures" /> and <see cref="AndroidKeyAttestationStatusEmbeddedFailures" />).
///     </para>
/// </remarks>
public class DefaultAndroidKeyAttestationStatusProvider : IAndroidKeyAttestationStatusProvider
{
    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatusProvider" />.
    /// </summary>
    /// <param name="httpClient">An HTTP client for downloading the status list.</param>
    /// <param name="safeJsonSerializer">Safe (exceptionless) JSON serializer.</param>
    /// <param name="counters">Counters for the metrics of the status list, used to count the status lists that are not provided.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidKeyAttestationStatusProvider(
        IAndroidKeyAttestationStatusHttpClient httpClient,
        ISafeJsonSerializer safeJsonSerializer,
        IAndroidKeyAttestationStatusCounters counters,
        ILogger<DefaultAndroidKeyAttestationStatusProvider> logger)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(safeJsonSerializer);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        HttpClient = httpClient;
        SafeJsonSerializer = safeJsonSerializer;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     An HTTP client for downloading the status list.
    /// </summary>
    protected IAndroidKeyAttestationStatusHttpClient HttpClient { get; }

    /// <summary>
    ///     Safe (exceptionless) JSON serializer.
    /// </summary>
    protected ISafeJsonSerializer SafeJsonSerializer { get; }

    /// <summary>
    ///     Counters for the metrics of the status list, used to count the status lists that are not provided.
    /// </summary>
    protected IAndroidKeyAttestationStatusCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAndroidKeyAttestationStatusProvider> Logger { get; }

    /// <inheritdoc />
    public virtual async Task<Result<AndroidKeyAttestationStatusListJSON>> DownloadStatusListAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        string json;
        try
        {
            json = await HttpClient.DownloadStatusListAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TimeoutException or IOException)
        {
            // The request failed, the response has an unsuccessful status code or exceeds the limits of the client, or the connection was broken.
            // A failed download is an expected failure rather than an exception: it is reported and counted with its reason, and the status list is not provided
            // (the background ingestion retries the download later).
            Logger.WarnDownloadFailed(exception);
            Counters.IncrementDownloadFailure(exception is TimeoutException
                ? AndroidKeyAttestationStatusDownloadFailures.Timeout
                : AndroidKeyAttestationStatusDownloadFailures.RequestFailed);
            return Result<AndroidKeyAttestationStatusListJSON>.Fail();
        }

        var statusListResult = Deserialize(json);
        if (statusListResult.HasError)
        {
            Logger.WarnDownloadedStatusListInvalid();
            Counters.IncrementDownloadFailure(AndroidKeyAttestationStatusDownloadFailures.ListInvalid);
            return Result<AndroidKeyAttestationStatusListJSON>.Fail();
        }

        return statusListResult;
    }

    /// <inheritdoc />
    /// <exception cref="ArgumentNullException"><paramref name="assembly" /> or <paramref name="resourceName" /> is <see langword="null" /></exception>
    /// <exception cref="ArgumentException"><paramref name="resourceName" /> is empty or consists only of white-space characters</exception>
    public virtual async Task<Result<AndroidKeyAttestationStatusListJSON>> LoadEmbeddedStatusListAsync(Assembly assembly, string resourceName, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(assembly);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceName);
        cancellationToken.ThrowIfCancellationRequested();
        var assemblyName = assembly.FullName;
        string json;
        await using (var resourceStream = assembly.GetManifestResourceStream(resourceName))
        {
            if (resourceStream is null)
            {
                Logger.WarnEmbeddedStatusListResourceNotFound(resourceName, assemblyName, FormatManifestResourceNames(assembly));
                Counters.IncrementEmbeddedFailure(AndroidKeyAttestationStatusEmbeddedFailures.ResourceNotFound);
                return Result<AndroidKeyAttestationStatusListJSON>.Fail();
            }

            using var reader = new StreamReader(resourceStream, Encoding.UTF8, true);
            json = await reader.ReadToEndAsync(cancellationToken);
        }

        var statusListResult = Deserialize(json);
        if (statusListResult.HasError)
        {
            Logger.WarnEmbeddedStatusListInvalid(resourceName, assemblyName);
            Counters.IncrementEmbeddedFailure(AndroidKeyAttestationStatusEmbeddedFailures.ListInvalid);
            return Result<AndroidKeyAttestationStatusListJSON>.Fail();
        }

        return statusListResult;
    }

    /// <summary>
    ///     Deserializes the status list, which has to match its documented JSON format: an object with an 'entries' object whose values are objects with the documented members.
    /// </summary>
    /// <param name="json">The status list in JSON.</param>
    /// <returns>If the status list matches its JSON format, the result contains <see cref="AndroidKeyAttestationStatusListJSON" />, otherwise the result indicates an error.</returns>
    protected virtual Result<AndroidKeyAttestationStatusListJSON> Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        // The serializer logs why the JSON can't be deserialized.
        var statusListResult = SafeJsonSerializer.DeserializeNonNullable<AndroidKeyAttestationStatusListJSON>(json);
        if (statusListResult.HasError || statusListResult.Ok.Entries is null)
        {
            return Result<AndroidKeyAttestationStatusListJSON>.Fail();
        }

        return statusListResult;
    }

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
}

/// <summary>
///     Extension methods for logging the provider of the certificate revocation status list of the Android attestation keys.
/// </summary>
public static partial class DefaultAndroidKeyAttestationStatusProviderLoggingExtensions
{
    /// <summary>
    ///     The status list of the Android attestation keys can't be downloaded
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">The exception of the HTTP client that describes the failure.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status list of the Android attestation keys can't be downloaded")]
    public static partial void WarnDownloadFailed(this ILogger logger, Exception exception);

    /// <summary>
    ///     The downloaded status list of the Android attestation keys doesn't match its JSON format (an object with an 'entries' object)
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The downloaded status list of the Android attestation keys doesn't match its JSON format (an object with an 'entries' object)")]
    public static partial void WarnDownloadedStatusListInvalid(this ILogger logger);

    /// <summary>
    ///     The status list of the Android attestation keys embedded in the application can't be loaded: the assembly '{Assembly}' doesn't contain the manifest resource '{ResourceName}' (the manifest resources of the assembly: {ResourceNames})
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="resourceName">The name of the manifest resource of the status list.</param>
    /// <param name="assembly">The full name of the assembly.</param>
    /// <param name="resourceNames">The names of the manifest resources of the assembly.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status list of the Android attestation keys embedded in the application can't be loaded: the assembly '{Assembly}' doesn't contain the manifest resource '{ResourceName}' (the manifest resources of the assembly: {ResourceNames})")]
    public static partial void WarnEmbeddedStatusListResourceNotFound(this ILogger logger, string resourceName, string? assembly, string resourceNames);

    /// <summary>
    ///     The status list of the Android attestation keys embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') doesn't match its JSON format (an object with an 'entries' object)
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="resourceName">The name of the manifest resource of the status list.</param>
    /// <param name="assembly">The full name of the assembly.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status list of the Android attestation keys embedded in the application (the manifest resource '{ResourceName}' of the assembly '{Assembly}') doesn't match its JSON format (an object with an 'entries' object)")]
    public static partial void WarnEmbeddedStatusListInvalid(this ILogger logger, string resourceName, string? assembly);
}
