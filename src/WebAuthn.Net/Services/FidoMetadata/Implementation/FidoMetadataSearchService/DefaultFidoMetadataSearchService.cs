using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService.Enums;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Metrics.Implementation;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.FidoMetadata;
using WebAuthn.Net.Storage.FidoMetadata.Models.Enums;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataSearchService{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultFidoMetadataSearchService<TContext> : IFidoMetadataSearchService<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataSearchService{TContext}" /> that doesn't report the absence of the metadata and the untrusted entries to the metrics and the log.
    /// </summary>
    /// <remarks>
    ///     Use <see cref="DefaultFidoMetadataSearchService{TContext}(IFidoMetadataSearchStorage{TContext}, ITimeProvider, IFidoMetadataCounters, ILogger{DefaultFidoMetadataSearchService{TContext}})" />
    ///     to count and log the lookups performed while no blob of the FIDO Metadata Service is available, and the lookups that have found an entry that doesn't allow to trust the authenticator.
    /// </remarks>
    /// <param name="metadataSearchStorage">The storage intended for searching in metadata obtained from the FIDO Metadata Service.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataSearchService(
        IFidoMetadataSearchStorage<TContext> metadataSearchStorage,
        ITimeProvider timeProvider)
        : this(metadataSearchStorage, timeProvider, NullFidoMetadataCounters.Instance, NullLogger<DefaultFidoMetadataSearchService<TContext>>.Instance)
    {
    }

    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataSearchService{TContext}" />.
    /// </summary>
    /// <param name="metadataSearchStorage">The storage intended for searching in metadata obtained from the FIDO Metadata Service.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <param name="counters">
    ///     Counters for FIDO Metadata Service metrics, used to count the lookups performed while no blob of the FIDO Metadata Service is available,
    ///     and the lookups that have found an entry that doesn't allow to trust the authenticator.
    /// </param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataSearchService(
        IFidoMetadataSearchStorage<TContext> metadataSearchStorage,
        ITimeProvider timeProvider,
        IFidoMetadataCounters counters,
        ILogger<DefaultFidoMetadataSearchService<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(metadataSearchStorage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        MetadataSearchStorage = metadataSearchStorage;
        TimeProvider = timeProvider;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     The storage intended for searching in metadata obtained from the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchStorage<TContext> MetadataSearchStorage { get; }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <summary>
    ///     Counters for FIDO Metadata Service metrics, used to count the lookups performed while no blob of the FIDO Metadata Service is available,
    ///     and the lookups that have found an entry that doesn't allow to trust the authenticator.
    /// </summary>
    protected IFidoMetadataCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultFidoMetadataSearchService<TContext>> Logger { get; }

    /// <inheritdoc />
    /// <remarks>
    ///     <para>
    ///         If no blob of the FIDO Metadata Service is available in the storage (for example, before the first successful ingestion), the result is <see cref="FidoMetadataSearchError.MetadataNotAvailable" />,
    ///         a <see cref="LogLevel.Warning" /> is logged and the lookup is counted (<see cref="IFidoMetadataCounters.IncrementLookupWithoutMetadata" />),
    ///         because such a lookup can't succeed for any authenticator until a blob is ingested.
    ///     </para>
    ///     <para>
    ///         If the entry for the <paramref name="aaguid" /> is found, but <see cref="CanTrustMetadata" /> doesn't trust it (for example, the status of the authenticator is REVOKED), the result is <see cref="FidoMetadataSearchError.Untrusted" />,
    ///         a <see cref="LogLevel.Warning" /> is logged and the lookup is counted (<see cref="IFidoMetadataCounters.IncrementLookupWithUntrustedEntry" />).
    ///     </para>
    /// </remarks>
    public virtual async Task<Result<FidoMetadataResult, FidoMetadataSearchError>> FindMetadataByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var storageResult = await MetadataSearchStorage.FindByAaguidAsync(context, aaguid, cancellationToken);
        if (storageResult.HasError)
        {
            if (storageResult.Error is FidoMetadataSearchStorageError.MetadataNotAvailable)
            {
                Logger.WarnMetadataNotAvailableForAaguid(aaguid);
                Counters.IncrementLookupWithoutMetadata();
                return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.MetadataNotAvailable);
            }

            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        var entry = storageResult.Ok;
        // The status reports are checked before the rest of the entry: an entry that doesn't allow to trust the authenticator rejects it
        // even if the entry would be unusable anyway (for example, has no metadata statement), because the attestation may still chain up to an embedded root certificate.
        if (!CanTrustMetadata(entry))
        {
            Logger.WarnMetadataUntrustedForAaguid(aaguid, FormatStatusReports(entry));
            Counters.IncrementLookupWithUntrustedEntry();
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.Untrusted);
        }

        if (entry.MetadataStatement is null)
        {
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        if (entry.MetadataStatement.Aaguid != aaguid)
        {
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        var metadata = HandleMetadataStatement(entry.MetadataStatement);
        if (metadata is null)
        {
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        return Result<FidoMetadataResult, FidoMetadataSearchError>.Success(metadata);
    }

    /// <inheritdoc />
    /// <remarks>
    ///     <para>
    ///         If no blob of the FIDO Metadata Service is available in the storage (for example, before the first successful ingestion), the result is <see cref="FidoMetadataSearchError.MetadataNotAvailable" />,
    ///         a <see cref="LogLevel.Warning" /> is logged and the lookup is counted (<see cref="IFidoMetadataCounters.IncrementLookupWithoutMetadata" />),
    ///         because such a lookup can't succeed for any authenticator until a blob is ingested.
    ///     </para>
    ///     <para>
    ///         If the entry for the <paramref name="subjectKeyIdentifier" /> is found, but <see cref="CanTrustMetadata" /> doesn't trust it (for example, the status of the authenticator is REVOKED),
    ///         the result is <see cref="FidoMetadataSearchError.Untrusted" />, a <see cref="LogLevel.Warning" /> is logged and the lookup is counted (<see cref="IFidoMetadataCounters.IncrementLookupWithUntrustedEntry" />).
    ///     </para>
    /// </remarks>
    public virtual async Task<Result<FidoMetadataResult, FidoMetadataSearchError>> FindMetadataBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(subjectKeyIdentifier);
        cancellationToken.ThrowIfCancellationRequested();
        var storageResult = await MetadataSearchStorage.FindBySubjectKeyIdentifierAsync(context, subjectKeyIdentifier, cancellationToken);
        if (storageResult.HasError)
        {
            if (storageResult.Error is FidoMetadataSearchStorageError.MetadataNotAvailable)
            {
                Logger.WarnMetadataNotAvailableForSubjectKeyIdentifier(Convert.ToHexString(subjectKeyIdentifier));
                Counters.IncrementLookupWithoutMetadata();
                return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.MetadataNotAvailable);
            }

            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        var entry = storageResult.Ok;
        // The status reports are checked before the rest of the entry: an entry that doesn't allow to trust the authenticator rejects it
        // even if the entry would be unusable anyway (for example, has no metadata statement).
        if (!CanTrustMetadata(entry))
        {
            Logger.WarnMetadataUntrustedForSubjectKeyIdentifier(Convert.ToHexString(subjectKeyIdentifier), FormatStatusReports(entry));
            Counters.IncrementLookupWithUntrustedEntry();
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.Untrusted);
        }

        if (entry.MetadataStatement is null)
        {
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        if (entry.AttestationCertificateKeyIdentifiers is null)
        {
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        if (!entry.AttestationCertificateKeyIdentifiers.Any(x => x.AsSpan().SequenceEqual(subjectKeyIdentifier.AsSpan())))
        {
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        var metadata = HandleMetadataStatement(entry.MetadataStatement);
        if (metadata is null)
        {
            return Result<FidoMetadataResult, FidoMetadataSearchError>.Fail(FidoMetadataSearchError.NotFound);
        }

        return Result<FidoMetadataResult, FidoMetadataSearchError>.Success(metadata);
    }

    /// <summary>
    ///     Verifies whether the status reports of the entry allow to trust the authenticator.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         An entry with a status report that indicates a security issue or the end of support (REVOKED, RETIRED, USER_VERIFICATION_BYPASS, ATTESTATION_KEY_COMPROMISE, USER_KEY_REMOTE_COMPROMISE,
    ///         USER_KEY_PHYSICAL_COMPROMISE or UPDATE_AVAILABLE) is not trusted, as well as an entry without any status report known to the library.
    ///     </para>
    ///     <para>
    ///         An entry that is not trusted makes the lookup return <see cref="FidoMetadataSearchError.Untrusted" />, and the attestation of the authenticator is rejected
    ///         even if it chains up to a root certificate embedded in the library.
    ///     </para>
    /// </remarks>
    /// <param name="blobEntry">The entry of the FIDO Metadata Service blob found for the authenticator.</param>
    /// <returns><see langword="true" /> if the entry allows to trust the authenticator, otherwise - <see langword="false" />.</returns>
    protected virtual bool CanTrustMetadata(MetadataBlobPayloadEntry blobEntry)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (blobEntry is null)
        {
            return false;
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (blobEntry.StatusReports is null || blobEntry.StatusReports.Length == 0)
        {
            return false;
        }

        foreach (var statusReport in blobEntry.StatusReports)
        {
            if (statusReport.Status == AuthenticatorStatus.REVOKED
                || statusReport.Status == AuthenticatorStatus.RETIRED
                || statusReport.Status == AuthenticatorStatus.USER_VERIFICATION_BYPASS
                || statusReport.Status == AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE
                || statusReport.Status == AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE
                || statusReport.Status == AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE
                || statusReport.Status == AuthenticatorStatus.UPDATE_AVAILABLE)
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    ///     Handles the found Metadata Statement, validating its compliance with rules and preparing the corresponding <see cref="FidoMetadataResult" /> in case of success.
    /// </summary>
    /// <param name="metadataStatement">The found <see cref="MetadataStatement" />.</param>
    /// <returns>An instance of <see cref="FidoMetadataResult" /> if the <see cref="MetadataStatement" /> complies with rules, otherwise - <see langword="null" />.</returns>
    protected virtual FidoMetadataResult? HandleMetadataStatement(MetadataStatement metadataStatement)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (metadataStatement is null)
        {
            return null;
        }

        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(metadataStatement.AttestationRootCertificates?.Length > 0))
        {
            return null;
        }

        var allowedRootCertificates = new List<byte[]>(metadataStatement.AttestationRootCertificates.Length);
        var currentDate = TimeProvider.GetPreciseUtcDateTime();
        foreach (var attestationRootCertificate in metadataStatement.AttestationRootCertificates)
        {
            if (!X509CertificateInMemoryLoader.TryLoad(attestationRootCertificate, out var certificate))
            {
                certificate?.Dispose();
                continue;
            }

            if (!(currentDate < certificate.NotBefore || currentDate > certificate.NotAfter))
            {
                allowedRootCertificates.Add(attestationRootCertificate);
            }

            certificate.Dispose();
        }

        if (allowedRootCertificates.Count == 0)
        {
            return null;
        }

        var result = new FidoMetadataResult(allowedRootCertificates.ToArray(), metadataStatement.AttestationTypes);
        return result;
    }

    // the statuses of the entry for the log message, in the order of its status reports (the reports with statuses unknown to the library are skipped during decoding)
    private static string FormatStatusReports(MetadataBlobPayloadEntry blobEntry)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (blobEntry.StatusReports is null || blobEntry.StatusReports.Length == 0)
        {
            return "none known to the library";
        }

        return string.Join(", ", blobEntry.StatusReports.Select(static x => x.Status.ToString()));
    }
}

/// <summary>
///     Extension methods for logging the search in the metadata obtained from the FIDO Metadata Service.
/// </summary>
public static partial class DefaultFidoMetadataSearchServiceLoggingExtensions
{
    /// <summary>
    ///     The storage contains no FIDO Metadata Service blob (no blob has been ingested yet), so the metadata for the authenticator with AAGUID {Aaguid} can't be found
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The storage contains no FIDO Metadata Service blob (no blob has been ingested yet), so the metadata for the authenticator with AAGUID {Aaguid} can't be found")]
    public static partial void WarnMetadataNotAvailableForAaguid(this ILogger logger, Guid aaguid);

    /// <summary>
    ///     The storage contains no FIDO Metadata Service blob (no blob has been ingested yet), so the metadata for the authenticator with the attestation certificate key identifier {SubjectKeyIdentifier} can't be found
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="subjectKeyIdentifier">The subject key identifier of the attestation certificate, in hexadecimal.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The storage contains no FIDO Metadata Service blob (no blob has been ingested yet), so the metadata for the authenticator with the attestation certificate key identifier {SubjectKeyIdentifier} can't be found")]
    public static partial void WarnMetadataNotAvailableForSubjectKeyIdentifier(this ILogger logger, string subjectKeyIdentifier);

    /// <summary>
    ///     The status reports of the FIDO Metadata Service entry for the authenticator with AAGUID {Aaguid} don't allow to trust the authenticator: {StatusReports}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="aaguid">The AAGUID of the authenticator.</param>
    /// <param name="statusReports">The statuses of the status reports of the entry, comma-separated.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status reports of the FIDO Metadata Service entry for the authenticator with AAGUID {Aaguid} don't allow to trust the authenticator: {StatusReports}")]
    public static partial void WarnMetadataUntrustedForAaguid(this ILogger logger, Guid aaguid, string statusReports);

    /// <summary>
    ///     The status reports of the FIDO Metadata Service entry for the authenticator with the attestation certificate key identifier {SubjectKeyIdentifier} don't allow to trust the authenticator: {StatusReports}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="subjectKeyIdentifier">The subject key identifier of the attestation certificate, in hexadecimal.</param>
    /// <param name="statusReports">The statuses of the status reports of the entry, comma-separated.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status reports of the FIDO Metadata Service entry for the authenticator with the attestation certificate key identifier {SubjectKeyIdentifier} don't allow to trust the authenticator: {StatusReports}")]
    public static partial void WarnMetadataUntrustedForSubjectKeyIdentifier(this ILogger logger, string subjectKeyIdentifier, string statusReports);
}
