using System;
using System.Linq;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;

namespace WebAuthn.Net.DSL;

/// <summary>
///     Edits of a decoded FIDO Metadata Service blob, for the tests that need entries the downloaded blob doesn't have.
///     Every edit returns a copy of the blob with the same legal header, serial number and next update date.
/// </summary>
internal static class MetadataBlobPayloadEdits
{
    // The entry of the "Android Authenticator" (the Android platform authenticator), which lists the Google Hardware Attestation roots that the Android Key test vector chains up to
    public static readonly Guid AndroidAuthenticatorAaguid = Guid.Parse("b93fd961-f2e6-462f-b122-82002247de78");

    // The entry of the "YubiKey 5 Series", which lists only "basic_full" with the Yubico roots
    public static readonly Guid YubiKey5Aaguid = Guid.Parse("cb69481e-8ff7-4039-93ec-0a2729a154a8");

    /// <summary>
    ///     Returns a copy of the blob in which <paramref name="aaguid" /> has a copy of the entry of <paramref name="sourceAaguid" /> (the same metadata statement and status reports),
    ///     with other attestation types or attestation root certificates if they are specified. An existing entry for <paramref name="aaguid" /> is replaced.
    /// </summary>
    public static MetadataBlobPayload WithEntryCopy(
        this MetadataBlobPayload blob,
        Guid aaguid,
        Guid sourceAaguid,
        AuthenticatorAttestationType[]? attestationTypes = null,
        byte[][]? attestationRootCertificates = null)
    {
        ArgumentNullException.ThrowIfNull(blob);
        var source = blob.Entries.Single(x => x.Aaguid == sourceAaguid);
        var statement = source.MetadataStatement ?? throw new InvalidOperationException($"The entry of {sourceAaguid} has no metadata statement");
        var statementCopy = new MetadataStatement(
            statement.LegalHeader,
            statement.Aaid,
            aaguid,
            statement.AttestationCertificateKeyIdentifiers,
            statement.FriendlyNames,
            statement.Description,
            statement.AlternativeDescriptions,
            statement.AuthenticatorVersion,
            statement.ProtocolFamily,
            statement.Schema,
            statement.Upv,
            statement.AuthenticationAlgorithms,
            statement.PublicKeyAlgAndEncodings,
            attestationTypes ?? statement.AttestationTypes,
            statement.UserVerificationDetails,
            statement.KeyProtection,
            statement.IsKeyRestricted,
            statement.IsFreshUserVerificationRequired,
            statement.MatcherProtection,
            statement.CryptoStrength,
            statement.AttachmentHint,
            statement.TcDisplay,
            statement.TcDisplayContentType,
            statement.TcDisplayPngCharacteristics,
            attestationRootCertificates ?? statement.AttestationRootCertificates,
            statement.EcdaaTrustAnchors,
            statement.Icon,
            statement.IconDark,
            statement.ProviderLogoLight,
            statement.ProviderLogoDark,
            statement.SupportedExtensions,
            statement.MultiDeviceCredentialSupport,
            statement.AuthenticatorGetInfo,
            statement.CxConfigUrl);
        var entryCopy = new MetadataBlobPayloadEntry(
            source.Aaid,
            aaguid,
            source.AttestationCertificateKeyIdentifiers,
            statementCopy,
            source.BiometricStatusReports,
            source.StatusReports,
            source.TimeOfLastStatusChange,
            source.RogueListUrl,
            source.RogueListHash);
        var entries = blob.Entries.Where(x => x.Aaguid != aaguid).Append(entryCopy).ToArray();
        return new(blob.LegalHeader, blob.No, blob.NextUpdate, entries);
    }

    /// <summary>
    ///     Returns a copy of the blob without the entry of <paramref name="aaguid" />.
    /// </summary>
    public static MetadataBlobPayload WithoutEntry(this MetadataBlobPayload blob, Guid aaguid)
    {
        ArgumentNullException.ThrowIfNull(blob);
        return new(blob.LegalHeader, blob.No, blob.NextUpdate, blob.Entries.Where(x => x.Aaguid != aaguid).ToArray());
    }
}
