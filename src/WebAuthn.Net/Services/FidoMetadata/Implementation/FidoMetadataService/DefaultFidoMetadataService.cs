using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataService;
using WebAuthn.Net.Services.Static;
using WebAuthn.Net.Storage.Operations;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataService;

public class DefaultFidoMetadataService<TContext> : IFidoMetadataService<TContext>
    where TContext : class, IWebAuthnContext
{
    public DefaultFidoMetadataService(IFidoMetadataStorage metadataStorage)
    {
        ArgumentNullException.ThrowIfNull(metadataStorage);
        MetadataStorage = metadataStorage;
    }

    protected IFidoMetadataStorage MetadataStorage { get; }

    public virtual async Task<FidoMetadataSearchResult?> FindMetadataAsync(
        TContext context,
        byte[] aaguidBytes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (aaguidBytes is null)
        {
            return null;
        }

        var aaguidHex = Convert.ToHexString(aaguidBytes);
        if (!Guid.TryParse(aaguidHex, out var aaguid))
        {
            return null;
        }

        var entry = await MetadataStorage.FindAsync(aaguid, cancellationToken);
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

        // ReSharper disable once ConditionalAccessQualifierIsNonNullableAccordingToAPIContract
        if (!(entry.MetadataStatement.AttestationRootCertificates?.Length > 0))
        {
            return null;
        }

        var allowedRootCertificates = new List<byte[]>(entry.MetadataStatement.AttestationRootCertificates.Length);
        foreach (var attestationRootCertificate in entry.MetadataStatement.AttestationRootCertificates)
        {
            using var certificate = X509CertificateInMemoryLoader.Load(attestationRootCertificate);
            if (certificate.GetECDsaPublicKey() is { } ecdsaPublicKey)
            {
                ecdsaPublicKey.Dispose();
                allowedRootCertificates.Add(attestationRootCertificate);
            }
            else if (certificate.GetRSAPublicKey() is { } rsaPublicKey)
            {
                rsaPublicKey.Dispose();
                allowedRootCertificates.Add(attestationRootCertificate);
            }
        }

        if (allowedRootCertificates.Count < 1)
        {
            return null;
        }

        return new(allowedRootCertificates.ToArray(), entry.MetadataStatement.AttestationTypes);
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
