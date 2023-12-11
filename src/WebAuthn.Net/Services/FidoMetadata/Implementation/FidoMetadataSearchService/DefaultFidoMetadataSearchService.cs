using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.Providers;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.FidoMetadata;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataSearchService;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataSearchService{TContext}" />.
/// </summary>
/// <typeparam name="TContext">The type of context in which the WebAuthn operation will be performed.</typeparam>
public class DefaultFidoMetadataSearchService<TContext> : IFidoMetadataSearchService<TContext>
    where TContext : class, IWebAuthnContext
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataSearchService{TContext}" />.
    /// </summary>
    /// <param name="metadataSearchStorage">The storage intended for searching in metadata obtained from the FIDO Metadata Service.</param>
    /// <param name="timeProvider">Current time provider.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataSearchService(
        IFidoMetadataSearchStorage<TContext> metadataSearchStorage,
        ITimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(metadataSearchStorage);
        ArgumentNullException.ThrowIfNull(timeProvider);
        MetadataSearchStorage = metadataSearchStorage;
        TimeProvider = timeProvider;
    }

    /// <summary>
    ///     The storage intended for searching in metadata obtained from the FIDO Metadata Service.
    /// </summary>
    protected IFidoMetadataSearchStorage<TContext> MetadataSearchStorage { get; }

    /// <summary>
    ///     Current time provider.
    /// </summary>
    protected ITimeProvider TimeProvider { get; }

    /// <inheritdoc />
    public virtual async Task<FidoMetadataResult?> FindMetadataByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var entry = await MetadataSearchStorage.FindByAaguidAsync(context, aaguid, cancellationToken);
        if (entry is null)
        {
            return null;
        }

        if (!CanTrustMetadata(entry))
        {
            return null;
        }

        if (entry.MetadataStatement is null)
        {
            return null;
        }

        if (entry.MetadataStatement.Aaguid != aaguid)
        {
            return null;
        }

        return HandleMetadataStatement(entry.MetadataStatement);
    }

    /// <inheritdoc />
    public virtual async Task<FidoMetadataResult?> FindMetadataBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var entry = await MetadataSearchStorage.FindBySubjectKeyIdentifierAsync(context, subjectKeyIdentifier, cancellationToken);
        if (entry is null)
        {
            return null;
        }

        if (!CanTrustMetadata(entry))
        {
            return null;
        }

        if (entry.MetadataStatement is null)
        {
            return null;
        }

        if (entry.AttestationCertificateKeyIdentifiers is null)
        {
            return null;
        }

        if (!entry.AttestationCertificateKeyIdentifiers.Any(x => x.AsSpan().SequenceEqual(subjectKeyIdentifier.AsSpan())))
        {
            return null;
        }

        return HandleMetadataStatement(entry.MetadataStatement);
    }

    /// <summary>
    ///     Verifies if the metadata can be trusted.
    /// </summary>
    /// <param name="blobEntry"></param>
    /// <returns></returns>
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
}
