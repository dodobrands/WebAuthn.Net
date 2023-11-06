using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.FidoMetadata;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataService;

public class DefaultFidoMetadataService<TContext> : IFidoMetadataService<TContext>
    where TContext : class, IWebAuthnContext
{
    public DefaultFidoMetadataService(IFidoMetadataStorage<TContext> metadataStorage)
    {
        ArgumentNullException.ThrowIfNull(metadataStorage);
        MetadataStorage = metadataStorage;
    }

    protected IFidoMetadataStorage<TContext> MetadataStorage { get; }

    public virtual async Task<Optional<FidoMetadataResult>> FindMetadataByAaguidAsync(
        TContext context,
        Guid aaguid,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var entry = await MetadataStorage.FindByAaguidAsync(context, aaguid, cancellationToken);
        if (entry is null)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        if (!CanTrustMetadata(entry))
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        if (entry.MetadataStatement is null)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        if (entry.MetadataStatement.Aaguid != aaguid)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        return HandleMetadataStatement(entry.MetadataStatement);
    }

    public async Task<Optional<FidoMetadataResult>> FindMetadataBySubjectKeyIdentifierAsync(
        TContext context,
        byte[] subjectKeyIdentifier,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var entry = await MetadataStorage.FindBySubjectKeyIdentifierAsync(context, subjectKeyIdentifier, cancellationToken);
        if (entry is null)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        if (!CanTrustMetadata(entry))
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        if (entry.MetadataStatement is null)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        if (entry.AttestationCertificateKeyIdentifiers is null)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        if (!entry.AttestationCertificateKeyIdentifiers.Any(x => x.AsSpan().SequenceEqual(subjectKeyIdentifier.AsSpan())))
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        return HandleMetadataStatement(entry.MetadataStatement);
    }

    protected virtual Optional<FidoMetadataResult> HandleMetadataStatement(MetadataStatement metadataStatement)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (metadataStatement is null)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(metadataStatement.AttestationRootCertificates?.Length > 0))
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        var allowedRootCertificates = new List<byte[]>(metadataStatement.AttestationRootCertificates.Length);
        foreach (var attestationRootCertificate in metadataStatement.AttestationRootCertificates)
        {
            if (!X509CertificateInMemoryLoader.TryLoad(attestationRootCertificate, out var certificate))
            {
                certificate?.Dispose();
                continue;
            }

            certificate.Dispose();
            allowedRootCertificates.Add(attestationRootCertificate);
        }

        if (allowedRootCertificates.Count < 1)
        {
            return Optional<FidoMetadataResult>.Empty();
        }

        var result = new FidoMetadataResult(allowedRootCertificates.ToArray(), metadataStatement.AttestationTypes);
        return Optional<FidoMetadataResult>.Payload(result);
    }


    protected virtual bool CanTrustMetadata(MetadataBlobPayloadEntry blobEntry)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (blobEntry is null)
        {
            return false;
        }

        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(blobEntry.StatusReports?.Length > 1))
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
}
