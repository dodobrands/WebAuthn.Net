using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;
using Version = WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Version;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataDecoder" />.
/// </summary>
/// <remarks>
///     <para>
///         The entries of the blob are decoded independently of each other, as required by the
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-blob-proc-rules">Metadata BLOB object processing rules</a>.
///         An entry that is missing a required member, contains a value that cannot be decoded, or contains an unknown value of an enumerated type is skipped as a whole (so that no negative information about an authenticator can be lost by dropping only a part of the entry),
///         and a warning is logged with the identifier of the skipped entry. Skipped entries do not affect the decoding of other entries.
///     </para>
///     <para>
///         There are two exceptions. The first one is the <c>status</c> member of a status report: according to the
///         <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat">AuthenticatorStatus enum</a> section, FIDO Servers MUST silently ignore all unknown <see cref="AuthenticatorStatus" /> values.
///         Therefore, a status report with a status unknown to the library is ignored, and the rest of the entry is decoded as usual.
///     </para>
///     <para>
///         The second one is the <c>vendorPrototypeConfigCommands</c> member of <c>authenticatorGetInfo</c>: its values are 64-bit unsigned integers, but some producers of metadata statements
///         serialize them through double-precision floating-point numbers and emit values outside the uint64 range. Such a value carries no security-relevant information about the authenticator,
///         so only the invalid value is ignored, and the rest of the entry is decoded as usual.
///     </para>
///     <para>
///         Skipped entries, ignored status reports and ignored values are not only logged, but also counted by <see cref="IFidoMetadataCounters" />, so that the problems of decoding the blob are visible in the monitoring.
///     </para>
///     <para>
///         The decoding of the whole blob fails only if the payload itself is invalid (for example, the <c>entries</c> member is missing) or if the blob contains entries, but none of them could be decoded.
///     </para>
/// </remarks>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultFidoMetadataDecoder : IFidoMetadataDecoder
{
    private const string EntryIdentifierPlaceholder = "<unknown>";

    /// <summary>
    ///     Constructs <see cref="DefaultFidoMetadataDecoder" />
    /// </summary>
    /// <param name="userVerificationMethodSerializer">Serializer for the <see cref="UserVerificationMethod" /> enum.</param>
    /// <param name="protocolFamilySerializer">Serializer for the <see cref="ProtocolFamily" /> enum.</param>
    /// <param name="authenticationAlgorithmSerializer">Serializer for the <see cref="AuthenticationAlgorithm" /> enum.</param>
    /// <param name="publicKeyRepresentationFormatSerializer">Serializer for the <see cref="PublicKeyRepresentationFormat" /> enum.</param>
    /// <param name="authenticatorAttestationTypeSerializer">Serializer for the <see cref="AuthenticatorAttestationType" /> enum.</param>
    /// <param name="keyProtectionTypeSerializer">Serializer for the <see cref="KeyProtectionType" /> enum.</param>
    /// <param name="matcherProtectionTypeSerializer">Serializer for the <see cref="MatcherProtectionType" /> enum.</param>
    /// <param name="authenticatorAttachmentHintSerializer">Serializer for the <see cref="AuthenticatorAttachmentHint" /> enum.</param>
    /// <param name="transactionConfirmationDisplayTypeSerializer">Serializer for the <see cref="TransactionConfirmationDisplayType" /> enum.</param>
    /// <param name="authenticatorStatusSerializer">Serializer for the <see cref="AuthenticatorStatus" /> enum.</param>
    /// <param name="counters">Counters for FIDO Metadata Service metrics.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoMetadataDecoder(
        IEnumMemberAttributeSerializer<UserVerificationMethod> userVerificationMethodSerializer,
        IEnumMemberAttributeSerializer<ProtocolFamily> protocolFamilySerializer,
        IEnumMemberAttributeSerializer<AuthenticationAlgorithm> authenticationAlgorithmSerializer,
        IEnumMemberAttributeSerializer<PublicKeyRepresentationFormat> publicKeyRepresentationFormatSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorAttestationType> authenticatorAttestationTypeSerializer,
        IEnumMemberAttributeSerializer<KeyProtectionType> keyProtectionTypeSerializer,
        IEnumMemberAttributeSerializer<MatcherProtectionType> matcherProtectionTypeSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorAttachmentHint> authenticatorAttachmentHintSerializer,
        IEnumMemberAttributeSerializer<TransactionConfirmationDisplayType> transactionConfirmationDisplayTypeSerializer,
        IEnumMemberAttributeSerializer<AuthenticatorStatus> authenticatorStatusSerializer,
        IFidoMetadataCounters counters,
        ILogger<DefaultFidoMetadataDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(userVerificationMethodSerializer);
        ArgumentNullException.ThrowIfNull(protocolFamilySerializer);
        ArgumentNullException.ThrowIfNull(authenticationAlgorithmSerializer);
        ArgumentNullException.ThrowIfNull(publicKeyRepresentationFormatSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorAttestationTypeSerializer);
        ArgumentNullException.ThrowIfNull(keyProtectionTypeSerializer);
        ArgumentNullException.ThrowIfNull(matcherProtectionTypeSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorAttachmentHintSerializer);
        ArgumentNullException.ThrowIfNull(transactionConfirmationDisplayTypeSerializer);
        ArgumentNullException.ThrowIfNull(authenticatorStatusSerializer);
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        UserVerificationMethodSerializer = userVerificationMethodSerializer;
        ProtocolFamilySerializer = protocolFamilySerializer;
        AuthenticationAlgorithmSerializer = authenticationAlgorithmSerializer;
        PublicKeyRepresentationFormatSerializer = publicKeyRepresentationFormatSerializer;
        AuthenticatorAttestationTypeSerializer = authenticatorAttestationTypeSerializer;
        KeyProtectionTypeSerializer = keyProtectionTypeSerializer;
        MatcherProtectionTypeSerializer = matcherProtectionTypeSerializer;
        AuthenticatorAttachmentHintSerializer = authenticatorAttachmentHintSerializer;
        TransactionConfirmationDisplayTypeSerializer = transactionConfirmationDisplayTypeSerializer;
        AuthenticatorStatusSerializer = authenticatorStatusSerializer;
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Serializer for the <see cref="UserVerificationMethodSerializer" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<UserVerificationMethod> UserVerificationMethodSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="ProtocolFamily" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<ProtocolFamily> ProtocolFamilySerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticationAlgorithm" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticationAlgorithm> AuthenticationAlgorithmSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="PublicKeyRepresentationFormat" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<PublicKeyRepresentationFormat> PublicKeyRepresentationFormatSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorAttestationType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorAttestationType> AuthenticatorAttestationTypeSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="KeyProtectionType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<KeyProtectionType> KeyProtectionTypeSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="MatcherProtectionType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<MatcherProtectionType> MatcherProtectionTypeSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorAttachmentHint" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorAttachmentHint> AuthenticatorAttachmentHintSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="TransactionConfirmationDisplayType" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<TransactionConfirmationDisplayType> TransactionConfirmationDisplayTypeSerializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AuthenticatorStatus" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AuthenticatorStatus> AuthenticatorStatusSerializer { get; }

    /// <summary>
    ///     Counters for FIDO Metadata Service metrics.
    /// </summary>
    protected IFidoMetadataCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultFidoMetadataDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<MetadataBlobPayload> Decode(MetadataBLOBPayloadJSON json)
    {
        Counters.IncrementDecodeStart();
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (json is null)
        {
            Counters.IncrementDecodeEnd(false);
            return Result<MetadataBlobPayload>.Fail();
        }

        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayload-entries
        // List of zero or more MetadataBLOBPayloadEntry objects.
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (json.Entries is null)
        {
            Logger.WarnEntriesMissing(json.No);
            Counters.IncrementDecodeEnd(false);
            return Result<MetadataBlobPayload>.Fail();
        }

        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayload-nextupdate
        // The use of the "nextUpdate" field is discouraged and the field will be removed in the future.
        // FIDO servers should ensure this field is not required by their code.
        DateTimeOffset? nextUpdate = null;
        if (json.NextUpdate is not null && !TryDecodeIso8601Date(json.NextUpdate, out nextUpdate))
        {
            Logger.WarnNextUpdateIgnored(json.No, json.NextUpdate);
            nextUpdate = null;
        }

        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-mds-blob-proc-rules
        // Iterate through the individual entries (of type MetadataBLOBPayloadEntry).
        // It is possible that an MDS entry representing an authenticator disappears in a future update of the BLOB.
        // This should not affect the processing of any other MDS entries.
        var entries = DecodeEntries(json.Entries);
        if (json.Entries.Length > 0 && entries.Length == 0)
        {
            // If the blob contains entries, but none of them could be decoded, the problem is not in the individual entries,
            // so the whole blob is rejected to prevent replacing the previously ingested metadata with an empty set.
            Logger.WarnNoEntriesDecoded(json.No, json.Entries.Length);
            Counters.IncrementDecodeEnd(false);
            return Result<MetadataBlobPayload>.Fail();
        }

        if (entries.Length != json.Entries.Length)
        {
            Logger.InfoEntriesSkipped(json.No, entries.Length, json.Entries.Length, json.Entries.Length - entries.Length);
        }

        var result = new MetadataBlobPayload(
            json.LegalHeader,
            json.No,
            nextUpdate,
            entries);
        Counters.IncrementDecodeEnd(true);
        return Result<MetadataBlobPayload>.Success(result);
    }

    private MetadataBlobPayloadEntry[] DecodeEntries(MetadataBLOBPayloadEntryJSON[] entries)
    {
        var result = new List<MetadataBlobPayloadEntry>(entries.Length);
        for (var i = 0; i < entries.Length; i++)
        {
            if (TryDecodeEntryWithoutExceptions(i, entries[i], out var decodedEntry))
            {
                result.Add(decodedEntry);
            }
        }

        return result.ToArray();
    }

    // The decoded models validate their arguments in the constructors, therefore the decoding of a malformed entry
    // can end with an exception even if all the inputs are checked beforehand. A single malformed entry must never
    // interrupt the decoding of the other entries nor break the ingestion of the whole blob.
    [SuppressMessage("Design", "CA1031:Do not catch general exception types")]
    private bool TryDecodeEntryWithoutExceptions(int index, MetadataBLOBPayloadEntryJSON entry, [NotNullWhen(true)] out MetadataBlobPayloadEntry? result)
    {
        var identifier = GetEntryIdentifier(entry);
        try
        {
            if (TryDecodeEntry(index, identifier, entry, out result, out var failedMember))
            {
                return true;
            }

            Logger.WarnEntrySkipped(index, identifier, failedMember);
            Counters.IncrementEntrySkipped(NormalizeMemberPath(failedMember));
            return false;
        }
        catch (Exception exception)
        {
            Logger.WarnEntrySkippedDueToException(exception, index, identifier);
            Counters.IncrementEntrySkippedDueToException();
            result = null;
            return false;
        }
    }

    // Removes array indices from the path of a member (for example, "statusReports[3].effectiveDate" becomes "statusReports[].effectiveDate"),
    // so that the set of values used as a metric tag stays bounded by the schema of the blob instead of growing with the size of its arrays.
    private static string NormalizeMemberPath(string memberPath)
    {
        if (!memberPath.Contains('[', StringComparison.Ordinal))
        {
            return memberPath;
        }

        var result = new StringBuilder(memberPath.Length);
        var insideIndex = false;
        foreach (var symbol in memberPath)
        {
            if (insideIndex)
            {
                if (symbol == ']')
                {
                    insideIndex = false;
                    result.Append(symbol);
                }

                continue;
            }

            if (symbol == '[')
            {
                insideIndex = true;
            }

            result.Append(symbol);
        }

        return result.ToString();
    }

    private static string GetEntryIdentifier(MetadataBLOBPayloadEntryJSON entry)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (entry is null)
        {
            return EntryIdentifierPlaceholder;
        }

        if (!string.IsNullOrEmpty(entry.Aaguid))
        {
            return entry.Aaguid;
        }

        if (!string.IsNullOrEmpty(entry.Aaid))
        {
            return entry.Aaid;
        }

        if (entry.AttestationCertificateKeyIdentifiers?.Length > 0 && !string.IsNullOrEmpty(entry.AttestationCertificateKeyIdentifiers[0]))
        {
            return entry.AttestationCertificateKeyIdentifiers[0];
        }

        return EntryIdentifierPlaceholder;
    }

    private bool TryDecodeEntry(int index, string identifier, MetadataBLOBPayloadEntryJSON entry, [NotNullWhen(true)] out MetadataBlobPayloadEntry? result, [NotNullWhen(false)] out string? failedMember)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (entry is null)
        {
            result = null;
            failedMember = "entry";
            return false;
        }

        Guid? aaguid = null;
        if (entry.Aaguid is not null)
        {
            if (!Guid.TryParse(entry.Aaguid, out var parsedAaguid))
            {
                result = null;
                failedMember = "aaguid";
                return false;
            }

            aaguid = parsedAaguid;
        }

        if (entry.Aaguid is null && entry.Aaid is null && entry.AttestationCertificateKeyIdentifiers is null)
        {
            result = null;
            failedMember = "aaid/aaguid/attestationCertificateKeyIdentifiers";
            return false;
        }

        byte[][]? attestationCertificateKeyIdentifiers = null;
        if (entry.AttestationCertificateKeyIdentifiers is not null && !TryDecodeAttestationCertificateKeyIdentifiers(entry.AttestationCertificateKeyIdentifiers, out attestationCertificateKeyIdentifiers))
        {
            result = null;
            failedMember = "attestationCertificateKeyIdentifiers";
            return false;
        }

        MetadataStatement? metadataStatement = null;
        if (entry.MetadataStatement is not null && !TryDecodeMetadataStatement(index, identifier, entry.MetadataStatement, out metadataStatement, out var failedMetadataStatementMember))
        {
            result = null;
            failedMember = $"metadataStatement.{failedMetadataStatementMember}";
            return false;
        }

        BiometricStatusReport[]? biometricStatusReports = null;
        if (entry.BiometricStatusReports is not null && !TryDecodeBiometricStatusReports(entry.BiometricStatusReports, out biometricStatusReports))
        {
            result = null;
            failedMember = "biometricStatusReports";
            return false;
        }

        if (!TryDecodeStatusReports(index, identifier, entry.StatusReports, out var statusReports, out var failedStatusReportsMember))
        {
            result = null;
            failedMember = failedStatusReportsMember;
            return false;
        }

        if (!TryDecodeIso8601Date(entry.TimeOfLastStatusChange, out var timeOfLastStatusChange))
        {
            result = null;
            failedMember = "timeOfLastStatusChange";
            return false;
        }

        // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-metadatablobpayloadentry-roguelisthash
        // This hash value MUST be present and non-empty whenever rogueListURL is present.
        if (entry.RogueListURL is not null && string.IsNullOrEmpty(entry.RogueListHash))
        {
            result = null;
            failedMember = "rogueListHash";
            return false;
        }

        result = new(
            entry.Aaid,
            aaguid,
            attestationCertificateKeyIdentifiers,
            metadataStatement,
            biometricStatusReports,
            statusReports,
            timeOfLastStatusChange.Value,
            entry.RogueListURL,
            entry.RogueListHash);
        failedMember = null;
        return true;
    }

    private bool TryDecodeMetadataStatement(int index, string identifier, MetadataStatementJSON metadataStatement, [NotNullWhen(true)] out MetadataStatement? result, [NotNullWhen(false)] out string? failedMember)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (metadataStatement is null)
        {
            result = null;
            failedMember = "metadataStatement";
            return false;
        }

        Guid? aaguid = null;
        if (metadataStatement.Aaguid is not null)
        {
            if (!Guid.TryParse(metadataStatement.Aaguid, out var parsedAaguid))
            {
                result = null;
                failedMember = "aaguid";
                return false;
            }

            aaguid = parsedAaguid;
        }

        byte[][]? attestationCertificateKeyIdentifiers = null;
        if (metadataStatement.AttestationCertificateKeyIdentifiers is not null && !TryDecodeAttestationCertificateKeyIdentifiers(metadataStatement.AttestationCertificateKeyIdentifiers, out attestationCertificateKeyIdentifiers))
        {
            result = null;
            failedMember = "attestationCertificateKeyIdentifiers";
            return false;
        }

        if (!ProtocolFamilySerializer.TryDeserialize(metadataStatement.ProtocolFamily, out var protocolFamily))
        {
            result = null;
            failedMember = "protocolFamily";
            return false;
        }

        if (!TryDecodeUpv(metadataStatement.Upv, out var upv))
        {
            result = null;
            failedMember = "upv";
            return false;
        }

        if (!TryDecodeAuthenticationAlgorithms(metadataStatement.AuthenticationAlgorithms, out var authenticationAlgorithms))
        {
            result = null;
            failedMember = "authenticationAlgorithms";
            return false;
        }

        if (!TryDecodePublicKeyAlgAndEncodings(metadataStatement.PublicKeyAlgAndEncodings, out var publicKeyAlgAndEncodings))
        {
            result = null;
            failedMember = "publicKeyAlgAndEncodings";
            return false;
        }

        if (!TryDecodeAttestationTypes(metadataStatement.AttestationTypes, out var attestationTypes))
        {
            result = null;
            failedMember = "attestationTypes";
            return false;
        }

        // https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#dom-metadatastatement-userverificationdetails
        // If this entry is missing, any user verification method could be implemented
        VerificationMethodDescriptor[][]? userVerificationDetails = null;
        if (metadataStatement.UserVerificationDetails is not null && !TryDecodeUserVerificationDetails(metadataStatement.UserVerificationDetails, out userVerificationDetails))
        {
            result = null;
            failedMember = "userVerificationDetails";
            return false;
        }

        if (!TryDecodeKeyProtection(metadataStatement.KeyProtection, out var keyProtection))
        {
            result = null;
            failedMember = "keyProtection";
            return false;
        }

        if (!TryDecodeMatcherProtection(metadataStatement.MatcherProtection, out var matcherProtection))
        {
            result = null;
            failedMember = "matcherProtection";
            return false;
        }

        AuthenticatorAttachmentHint[]? attachmentHint = null;
        if (metadataStatement.AttachmentHint is not null && !TryDecodeAttachmentHint(metadataStatement.AttachmentHint, out attachmentHint))
        {
            result = null;
            failedMember = "attachmentHint";
            return false;
        }

        if (!TryDecodeTcDisplay(metadataStatement.TcDisplay, out var tcDisplay))
        {
            result = null;
            failedMember = "tcDisplay";
            return false;
        }

        DisplayPngCharacteristicsDescriptor[]? tcDisplayPngCharacteristics = null;
        if (metadataStatement.TcDisplayPNGCharacteristics is not null && !TryDecodeTcDisplayPngCharacteristics(metadataStatement.TcDisplayPNGCharacteristics, out tcDisplayPngCharacteristics))
        {
            result = null;
            failedMember = "tcDisplayPNGCharacteristics";
            return false;
        }

        if (!TryDecodeAttestationRootCertificates(metadataStatement.AttestationRootCertificates, out var attestationRootCertificates))
        {
            result = null;
            failedMember = "attestationRootCertificates";
            return false;
        }

        EcdaaTrustAnchor[]? ecdaaTrustAnchors = null;
        if (metadataStatement.EcdaaTrustAnchors is not null && !TryDecodeEcdaaTrustAnchors(metadataStatement.EcdaaTrustAnchors, out ecdaaTrustAnchors))
        {
            result = null;
            failedMember = "ecdaaTrustAnchors";
            return false;
        }

        ExtensionDescriptor[]? supportedExtensions = null;
        if (metadataStatement.SupportedExtensions is not null && !TryDecodeSupportedExtensions(metadataStatement.SupportedExtensions, out supportedExtensions))
        {
            result = null;
            failedMember = "supportedExtensions";
            return false;
        }

        AuthenticatorGetInfo? authenticatorGetInfo = null;
        if (metadataStatement.AuthenticatorGetInfo is not null && !TryDecodeAuthenticatorGetInfo(index, identifier, metadataStatement.AuthenticatorGetInfo, out authenticatorGetInfo, out var failedAuthenticatorGetInfoMember))
        {
            result = null;
            failedMember = $"authenticatorGetInfo.{failedAuthenticatorGetInfoMember}";
            return false;
        }

        result = new(
            metadataStatement.LegalHeader,
            metadataStatement.Aaid,
            aaguid,
            attestationCertificateKeyIdentifiers,
            metadataStatement.FriendlyNames,
            metadataStatement.Description,
            metadataStatement.AlternativeDescriptions,
            metadataStatement.AuthenticatorVersion,
            protocolFamily.Value,
            metadataStatement.Schema,
            upv,
            authenticationAlgorithms,
            publicKeyAlgAndEncodings,
            attestationTypes,
            userVerificationDetails,
            keyProtection,
            metadataStatement.IsKeyRestricted,
            metadataStatement.IsFreshUserVerificationRequired,
            matcherProtection,
            metadataStatement.CryptoStrength,
            attachmentHint,
            tcDisplay,
            metadataStatement.TcDisplayContentType,
            tcDisplayPngCharacteristics,
            attestationRootCertificates,
            ecdaaTrustAnchors,
            metadataStatement.Icon,
            metadataStatement.IconDark,
            metadataStatement.ProviderLogoLight,
            metadataStatement.ProviderLogoDark,
            supportedExtensions,
            metadataStatement.MultiDeviceCredentialSupport,
            authenticatorGetInfo,
            metadataStatement.CxConfigUrl);
        failedMember = null;
        return true;
    }

    private static bool TryDecodeUpv(VersionJSON[] upv, [NotNullWhen(true)] out Version[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (upv is null)
        {
            result = null;
            return false;
        }

        result = new Version[upv.Length];
        for (var i = 0; i < upv.Length; i++)
        {
            if (!TryDecodeVersion(upv[i], out var version))
            {
                result = null;
                return false;
            }

            result[i] = version;
        }

        return true;
    }

    private static bool TryDecodeVersion(VersionJSON version, [NotNullWhen(true)] out Version? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (version is null)
        {
            result = null;
            return false;
        }

        result = new(version.Major, version.Minor);
        return true;
    }

    private bool TryDecodeAuthenticationAlgorithms(string[] authenticationAlgorithms, [NotNullWhen(true)] out AuthenticationAlgorithm[]? result)
    {
        return TryDecodeEnumMemberArray(authenticationAlgorithms, AuthenticationAlgorithmSerializer, out result);
    }

    private bool TryDecodePublicKeyAlgAndEncodings(string[] authenticationAlgorithms, [NotNullWhen(true)] out PublicKeyRepresentationFormat[]? result)
    {
        return TryDecodeEnumMemberArray(authenticationAlgorithms, PublicKeyRepresentationFormatSerializer, out result);
    }

    private bool TryDecodeAttestationTypes(string[] attestationTypes, [NotNullWhen(true)] out AuthenticatorAttestationType[]? result)
    {
        return TryDecodeEnumMemberArray(attestationTypes, AuthenticatorAttestationTypeSerializer, out result);
    }

    private bool TryDecodeUserVerificationDetails(VerificationMethodDescriptorJSON[][] userVerificationDetails, [NotNullWhen(true)] out VerificationMethodDescriptor[][]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (userVerificationDetails is null)
        {
            result = null;
            return false;
        }

        result = new VerificationMethodDescriptor[userVerificationDetails.Length][];
        for (var i = 0; i < userVerificationDetails.Length; i++)
        {
            if (!TryDecodeUserVerificationDetailsInner(userVerificationDetails[i], out var decodedUserVerificationDetails))
            {
                result = null;
                return false;
            }

            result[i] = decodedUserVerificationDetails;
        }

        return true;
    }

    private bool TryDecodeUserVerificationDetailsInner(VerificationMethodDescriptorJSON[] userVerificationDetails, [NotNullWhen(true)] out VerificationMethodDescriptor[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (userVerificationDetails is null)
        {
            result = null;
            return false;
        }

        result = new VerificationMethodDescriptor[userVerificationDetails.Length];
        for (var i = 0; i < userVerificationDetails.Length; i++)
        {
            if (!TryDecodeUserVerificationDetailsSingle(userVerificationDetails[i], out var decodedUserVerificationDetails))
            {
                result = null;
                return false;
            }

            result[i] = decodedUserVerificationDetails;
        }

        return true;
    }

    private bool TryDecodeUserVerificationDetailsSingle(VerificationMethodDescriptorJSON userVerificationDetails, [NotNullWhen(true)] out VerificationMethodDescriptor? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (userVerificationDetails is null)
        {
            result = null;
            return false;
        }

        UserVerificationMethod? userVerificationMethod = null;
        if (userVerificationDetails.UserVerificationMethod is not null
            && !UserVerificationMethodSerializer.TryDeserialize(userVerificationDetails.UserVerificationMethod, out userVerificationMethod))
        {
            result = null;
            return false;
        }

        CodeAccuracyDescriptor? caDesc = null;
        if (userVerificationDetails.CaDesc is not null && !TryDecodeCaDesc(userVerificationDetails.CaDesc, out caDesc))
        {
            result = null;
            return false;
        }

        BiometricAccuracyDescriptor? baDesc = null;
        if (userVerificationDetails.BaDesc is not null && !TryDecodeBaDesc(userVerificationDetails.BaDesc, out baDesc))
        {
            result = null;
            return false;
        }

        PatternAccuracyDescriptor? paDesc = null;
        if (userVerificationDetails.PaDesc is not null && !TryDecodePaDesc(userVerificationDetails.PaDesc, out paDesc))
        {
            result = null;
            return false;
        }

        result = new(
            userVerificationMethod,
            caDesc,
            baDesc,
            paDesc);
        return true;
    }

    private static bool TryDecodeCaDesc(CodeAccuracyDescriptorJSON caDesc, [NotNullWhen(true)] out CodeAccuracyDescriptor? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (caDesc is null)
        {
            result = null;
            return false;
        }

        result = new(
            caDesc.Base,
            caDesc.MinLength,
            caDesc.MaxRetries,
            caDesc.BlockSlowdown);
        return true;
    }

    private static bool TryDecodeBaDesc(BiometricAccuracyDescriptorJSON baDesc, [NotNullWhen(true)] out BiometricAccuracyDescriptor? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (baDesc is null)
        {
            result = null;
            return false;
        }

        result = new(
            baDesc.SelfAttestedFRR,
            baDesc.SelfAttestedFAR,
            baDesc.IaparThreshold,
            baDesc.MaxTemplates,
            baDesc.MaxRetries,
            baDesc.BlockSlowdown);
        return true;
    }

    private static bool TryDecodePaDesc(PatternAccuracyDescriptorJSON paDesc, [NotNullWhen(true)] out PatternAccuracyDescriptor? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (paDesc is null)
        {
            result = null;
            return false;
        }

        result = new(
            paDesc.MinComplexity,
            paDesc.MaxRetries,
            paDesc.BlockSlowdown);
        return true;
    }

    private bool TryDecodeKeyProtection(string[] keyProtection, [NotNullWhen(true)] out KeyProtectionType[]? result)
    {
        return TryDecodeEnumMemberArray(keyProtection, KeyProtectionTypeSerializer, out result);
    }

    private bool TryDecodeMatcherProtection(string[] matcherProtection, [NotNullWhen(true)] out MatcherProtectionType[]? result)
    {
        return TryDecodeEnumMemberArray(matcherProtection, MatcherProtectionTypeSerializer, out result);
    }

    private bool TryDecodeAttachmentHint(string[] attachmentHint, [NotNullWhen(true)] out AuthenticatorAttachmentHint[]? result)
    {
        return TryDecodeEnumMemberArray(attachmentHint, AuthenticatorAttachmentHintSerializer, out result);
    }

    private bool TryDecodeTcDisplay(string[] tcDisplay, [NotNullWhen(true)] out TransactionConfirmationDisplayType[]? result)
    {
        return TryDecodeEnumMemberArray(tcDisplay, TransactionConfirmationDisplayTypeSerializer, out result);
    }

    private static bool TryDecodeTcDisplayPngCharacteristics(DisplayPNGCharacteristicsDescriptorJSON[] tcDisplayPngCharacteristics, [NotNullWhen(true)] out DisplayPngCharacteristicsDescriptor[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (tcDisplayPngCharacteristics is null)
        {
            result = null;
            return false;
        }

        result = new DisplayPngCharacteristicsDescriptor[tcDisplayPngCharacteristics.Length];
        for (var i = 0; i < tcDisplayPngCharacteristics.Length; i++)
        {
            if (!TryDecodeDisplayPngCharacteristicsDescriptor(tcDisplayPngCharacteristics[i], out var tcDisplayPngCharacteristic))
            {
                result = null;
                return false;
            }

            result[i] = tcDisplayPngCharacteristic;
        }

        return true;
    }

    private static bool TryDecodeDisplayPngCharacteristicsDescriptor(DisplayPNGCharacteristicsDescriptorJSON tcDisplayPngCharacteristics, [NotNullWhen(true)] out DisplayPngCharacteristicsDescriptor? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (tcDisplayPngCharacteristics is null)
        {
            result = null;
            return false;
        }

        RgbPaletteEntry[]? plte = null;
        if (tcDisplayPngCharacteristics.Plte is not null && !TryDecodePlte(tcDisplayPngCharacteristics.Plte, out plte))
        {
            result = null;
            return false;
        }

        result = new(
            tcDisplayPngCharacteristics.Width,
            tcDisplayPngCharacteristics.Height,
            tcDisplayPngCharacteristics.BitDepth,
            tcDisplayPngCharacteristics.ColorType,
            tcDisplayPngCharacteristics.Compression,
            tcDisplayPngCharacteristics.Filter,
            tcDisplayPngCharacteristics.Interlace,
            plte);
        return true;
    }

    private static bool TryDecodePlte(RgbPaletteEntryJSON[] plte, [NotNullWhen(true)] out RgbPaletteEntry[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (plte is null)
        {
            result = null;
            return false;
        }

        result = new RgbPaletteEntry[plte.Length];
        for (var i = 0; i < plte.Length; i++)
        {
            if (!TryDecodeRgbPaletteEntry(plte[i], out var rgbPaletteEntry))
            {
                result = null;
                return false;
            }

            result[i] = rgbPaletteEntry;
        }

        return true;
    }

    private static bool TryDecodeRgbPaletteEntry(RgbPaletteEntryJSON plte, [NotNullWhen(true)] out RgbPaletteEntry? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (plte is null)
        {
            result = null;
            return false;
        }

        result = new(
            plte.R,
            plte.G,
            plte.B);
        return true;
    }

    private static bool TryDecodeAttestationRootCertificates(string[] attestationRootCertificates, [NotNullWhen(true)] out byte[][]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attestationRootCertificates is null)
        {
            result = null;
            return false;
        }

        result = new byte[attestationRootCertificates.Length][];
        for (var i = 0; i < attestationRootCertificates.Length; i++)
        {
            var attestationRootCertificateBase64 = attestationRootCertificates[i];
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (attestationRootCertificateBase64 is null || !Base64Raw.TryDecode(attestationRootCertificateBase64.Trim(), out var attestationRootCertificate))
            {
                result = null;
                return false;
            }

            result[i] = attestationRootCertificate;
        }

        return true;
    }

    private static bool TryDecodeEcdaaTrustAnchors(EcdaaTrustAnchorJSON[] ecdaaTrustAnchors, [NotNullWhen(true)] out EcdaaTrustAnchor[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (ecdaaTrustAnchors is null)
        {
            result = null;
            return false;
        }

        result = new EcdaaTrustAnchor[ecdaaTrustAnchors.Length];
        for (var i = 0; i < ecdaaTrustAnchors.Length; i++)
        {
            if (!TryDecodeEcdaaTrustAnchor(ecdaaTrustAnchors[i], out var ecdaaTrustAnchor))
            {
                result = null;
                return false;
            }

            result[i] = ecdaaTrustAnchor;
        }

        return true;
    }

    private static bool TryDecodeEcdaaTrustAnchor(EcdaaTrustAnchorJSON ecdaaTrustAnchor, [NotNullWhen(true)] out EcdaaTrustAnchor? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (ecdaaTrustAnchor is null)
        {
            result = null;
            return false;
        }

        if (!Base64Url.TryDecode(ecdaaTrustAnchor.X, out var x)
            || !Base64Url.TryDecode(ecdaaTrustAnchor.Y, out var y)
            || !Base64Url.TryDecode(ecdaaTrustAnchor.C, out var c)
            || !Base64Url.TryDecode(ecdaaTrustAnchor.Sx, out var sx)
            || !Base64Url.TryDecode(ecdaaTrustAnchor.Sy, out var sy))
        {
            result = null;
            return false;
        }

        result = new(
            x,
            y,
            c,
            sx,
            sy,
            ecdaaTrustAnchor.G1Curve);
        return true;
    }

    private static bool TryDecodeSupportedExtensions(ExtensionDescriptorJSON[] supportedExtensions, [NotNullWhen(true)] out ExtensionDescriptor[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (supportedExtensions is null)
        {
            result = null;
            return false;
        }

        result = new ExtensionDescriptor[supportedExtensions.Length];
        for (var i = 0; i < supportedExtensions.Length; i++)
        {
            if (!TryDecodeSupportedExtension(supportedExtensions[i], out var supportedExtension))
            {
                result = null;
                return false;
            }

            result[i] = supportedExtension;
        }

        return true;
    }

    private static bool TryDecodeSupportedExtension(ExtensionDescriptorJSON supportedExtension, [NotNullWhen(true)] out ExtensionDescriptor? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (supportedExtension is null)
        {
            result = null;
            return false;
        }

        result = new(supportedExtension.Id, supportedExtension.Tag, supportedExtension.Data, supportedExtension.FailIfUnknown);
        return true;
    }

    private bool TryDecodeAuthenticatorGetInfo(int index, string identifier, AuthenticatorGetInfoJSON authenticatorGetInfo, [NotNullWhen(true)] out AuthenticatorGetInfo? result, [NotNullWhen(false)] out string? failedMember)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticatorGetInfo is null)
        {
            result = null;
            failedMember = "authenticatorGetInfo";
            return false;
        }

        // https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorGetInfo
        // versions (0x01) - Array of strings - Required
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticatorGetInfo.Versions is null)
        {
            result = null;
            failedMember = "versions";
            return false;
        }

        if (!TryDecodeAuthenticatorGetInfoAaguid(authenticatorGetInfo.Aaguid, out var aaguid))
        {
            result = null;
            failedMember = "aaguid";
            return false;
        }

        FidoPublicKeyCredentialParameters[]? algorithms = null;
        if (authenticatorGetInfo.Algorithms?.Length > 0)
        {
            var resultAccumulator = new List<FidoPublicKeyCredentialParameters>(authenticatorGetInfo.Algorithms.Length);
            foreach (var algorithm in authenticatorGetInfo.Algorithms)
            {
                // https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialparameters-type
                // The value SHOULD be a member of PublicKeyCredentialType but client platforms MUST ignore unknown values,
                // ignoring any PublicKeyCredentialParameters with an unknown type.
                // https://www.w3.org/TR/webauthn-3/#enum-credentialType
                // enum PublicKeyCredentialType {
                //     "public-key"
                // };
                // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
                if (algorithm is null || algorithm.Type != "public-key")
                {
                    continue;
                }

                resultAccumulator.Add(new(algorithm.Type, algorithm.Alg));
            }

            if (resultAccumulator.Count > 0)
            {
                algorithms = resultAccumulator.ToArray();
            }
        }

        var vendorPrototypeConfigCommands = DecodeVendorPrototypeConfigCommands(index, identifier, authenticatorGetInfo.VendorPrototypeConfigCommands);

        result = new(
            authenticatorGetInfo.Versions,
            authenticatorGetInfo.Extensions,
            aaguid.Value,
            authenticatorGetInfo.Options,
            authenticatorGetInfo.MaxMsgSize,
            authenticatorGetInfo.PinUvAuthProtocols,
            authenticatorGetInfo.MaxCredentialCountInList,
            authenticatorGetInfo.MaxCredentialIdLength,
            authenticatorGetInfo.Transports,
            algorithms,
            authenticatorGetInfo.MaxSerializedLargeBlobArray,
            authenticatorGetInfo.ForcePINChange,
            authenticatorGetInfo.MinPINLength,
            authenticatorGetInfo.FirmwareVersion,
            authenticatorGetInfo.MaxCredBlobLength,
            authenticatorGetInfo.MaxRPIDsForSetMinPINLength,
            authenticatorGetInfo.PreferredPlatformUvAttempts,
            authenticatorGetInfo.UvModality,
            authenticatorGetInfo.Certifications,
            authenticatorGetInfo.RemainingDiscoverableCredentials,
            vendorPrototypeConfigCommands,
            authenticatorGetInfo.AttestationFormats,
            authenticatorGetInfo.UvCountSinceLastPinEntry,
            authenticatorGetInfo.LongTouchForReset,
            authenticatorGetInfo.EncIdentifier,
            authenticatorGetInfo.TransportsForReset,
            authenticatorGetInfo.PinComplexityPolicy,
            authenticatorGetInfo.PinComplexityPolicyURL,
            authenticatorGetInfo.MaxPINLength,
            authenticatorGetInfo.EncCredStoreState,
            authenticatorGetInfo.AuthenticatorConfigCommands);
        failedMember = null;
        return true;
    }

    private ulong[]? DecodeVendorPrototypeConfigCommands(int index, string identifier, JsonElement[]? vendorPrototypeConfigCommands)
    {
        if (vendorPrototypeConfigCommands is null)
        {
            return null;
        }

        // https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#authenticatorGetInfo
        // vendorPrototypeConfigCommands (0x15) - Array of Unsigned Integers - Optional
        // https://fidoalliance.org/specs/fido-v2.3.1-wd-20260529/fido-client-to-authenticator-protocol-v2.3.1-wd-20260529.html#vendorPrototype
        // vendorCommandId is a 64-bit unsigned integer, but some producers of metadata statements (for example, the JavaScript-based FIDO Conformance Tools)
        // serialize it through an IEEE 754 double, which turns 0xFFFFFFFFFFFFFFFF into 18446744073709552000 - a value outside the uint64 range.
        // The list of vendor prototype commands says nothing about the security of the authenticator, so instead of rejecting the whole entry,
        // only the invalid value is ignored. The ignored value is logged and counted so that the problem is visible in the monitoring.
        var result = new List<ulong>(vendorPrototypeConfigCommands.Length);
        for (var i = 0; i < vendorPrototypeConfigCommands.Length; i++)
        {
            var vendorCommand = vendorPrototypeConfigCommands[i];
            if (vendorCommand.ValueKind == JsonValueKind.Number && vendorCommand.TryGetUInt64(out var vendorCommandId))
            {
                result.Add(vendorCommandId);
                continue;
            }

            Logger.WarnVendorPrototypeConfigCommandIgnored(index, identifier, i, GetRawTextForLog(vendorCommand));
            Counters.IncrementValueIgnored("metadataStatement.authenticatorGetInfo.vendorPrototypeConfigCommands[]");
        }

        return result.ToArray();
    }

    private static string GetRawTextForLog(JsonElement element)
    {
        const int maxLength = 64;
        if (element.ValueKind == JsonValueKind.Undefined)
        {
            return "undefined";
        }

        // the raw text of a (pretty-printed) element may contain line breaks, which must not split the log record
        return LogValue.Sanitize(element.GetRawText(), maxLength);
    }

    private static bool TryDecodeAuthenticatorGetInfoAaguid(string aaguid, [NotNullWhen(true)] out Guid? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (aaguid is null)
        {
            result = null;
            return false;
        }

        // The FIDO Metadata Service publishes the AAGUID as a hex string (with or without dashes)
        if (Guid.TryParse(aaguid, out var parsedAaguid))
        {
            result = parsedAaguid;
            return true;
        }

        // https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#sctn-type-agid
        // All binary values are base64 encoded.
        if ((Base64Raw.TryDecode(aaguid, out var aaguidBytes) || Base64Url.TryDecode(aaguid, out aaguidBytes)) && aaguidBytes.Length == 16)
        {
            result = new Guid(Convert.ToHexString(aaguidBytes));
            return true;
        }

        result = null;
        return false;
    }

    private bool TryDecodeBiometricStatusReports(BiometricStatusReportJSON[] biometricStatusReports, [NotNullWhen(true)] out BiometricStatusReport[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (biometricStatusReports is null)
        {
            result = null;
            return false;
        }

        result = new BiometricStatusReport[biometricStatusReports.Length];
        for (var i = 0; i < biometricStatusReports.Length; i++)
        {
            if (!TryDecodeBiometricStatusReport(biometricStatusReports[i], out var biometricStatusReport))
            {
                result = null;
                return false;
            }

            result[i] = biometricStatusReport;
        }

        return true;
    }

    private bool TryDecodeBiometricStatusReport(BiometricStatusReportJSON biometricStatusReport, [NotNullWhen(true)] out BiometricStatusReport? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (biometricStatusReport is null)
        {
            result = null;
            return false;
        }

        if (!UserVerificationMethodSerializer.TryDeserialize(biometricStatusReport.Modality, out var modality))
        {
            result = null;
            return false;
        }

        DateTimeOffset? effectiveDate = null;
        if (biometricStatusReport.EffectiveDate is not null && !TryDecodeIso8601Date(biometricStatusReport.EffectiveDate, out effectiveDate))
        {
            result = null;
            return false;
        }

        result = new(
            biometricStatusReport.CertLevel,
            modality.Value,
            effectiveDate,
            biometricStatusReport.CertificationDescriptor,
            biometricStatusReport.CertificateNumber,
            biometricStatusReport.CertificationPolicyVersion,
            biometricStatusReport.CertificationRequirementsVersion);
        return true;
    }

    private bool TryDecodeStatusReports(int index, string identifier, StatusReportJSON[] statusReports, [NotNullWhen(true)] out StatusReport[]? result, [NotNullWhen(false)] out string? failedMember)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (statusReports is null)
        {
            result = null;
            failedMember = "statusReports";
            return false;
        }

        var decodedStatusReports = new List<StatusReport>(statusReports.Length);
        for (var i = 0; i < statusReports.Length; i++)
        {
            var statusReport = statusReports[i];
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (statusReport is null)
            {
                result = null;
                failedMember = $"statusReports[{i.ToString(CultureInfo.InvariantCulture)}]";
                return false;
            }

            // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dom-statusreport-status
            // The 'status' member is required, so a status report without it is malformed and the entry is skipped as a whole.
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (statusReport.Status is null)
            {
                result = null;
                failedMember = $"statusReports[{i.ToString(CultureInfo.InvariantCulture)}].status";
                return false;
            }

            // https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-authnr-stat
            // More values might be added in the future. FIDO Servers MUST silently ignore all unknown AuthenticatorStatus values.
            // Unlike any other invalid member, an unknown status doesn't make the entry invalid: only the status report is ignored,
            // and the rest of the entry is decoded as usual. The ignored status report is logged and counted instead of being ignored
            // completely silently, because it means that the library doesn't know a status defined by a newer version of the specification.
            // If none of the status reports of the entry is known, the entry is decoded with an empty array of status reports,
            // and the IFidoMetadataSearchService treats such an entry as untrusted.
            if (!AuthenticatorStatusSerializer.TryDeserialize(statusReport.Status, out var status))
            {
                Logger.WarnStatusReportIgnored(index, identifier, i, statusReport.Status);
                Counters.IncrementStatusReportIgnored(statusReport.Status);
                continue;
            }

            if (!TryDecodeStatusReport(statusReport, status.Value, out var decodedStatusReport, out var failedStatusReportMember))
            {
                result = null;
                failedMember = $"statusReports[{i.ToString(CultureInfo.InvariantCulture)}].{failedStatusReportMember}";
                return false;
            }

            decodedStatusReports.Add(decodedStatusReport);
        }

        result = decodedStatusReports.ToArray();
        failedMember = null;
        return true;
    }

    private static bool TryDecodeStatusReport(StatusReportJSON statusReport, AuthenticatorStatus status, [NotNullWhen(true)] out StatusReport? result, [NotNullWhen(false)] out string? failedMember)
    {
        DateTimeOffset? effectiveDate = null;
        if (statusReport.EffectiveDate is not null && !TryDecodeIso8601Date(statusReport.EffectiveDate, out effectiveDate))
        {
            result = null;
            failedMember = "effectiveDate";
            return false;
        }

        byte[]? batchCertificate = null;
        if (statusReport.BatchCertificate is not null)
        {
            if (!Base64Raw.TryDecode(statusReport.BatchCertificate, out var statusReportBatchCertificate))
            {
                result = null;
                failedMember = "batchCertificate";
                return false;
            }

            batchCertificate = statusReportBatchCertificate;
        }

        byte[]? certificate = null;
        if (statusReport.Certificate is not null)
        {
            if (!Base64Raw.TryDecode(statusReport.Certificate, out var statusReportCertificate))
            {
                result = null;
                failedMember = "certificate";
                return false;
            }

            certificate = statusReportCertificate;
        }

        DateTimeOffset? sunsetDate = null;
        if (statusReport.SunsetDate is not null)
        {
            if (!TryDecodeIso8601Date(statusReport.SunsetDate, out var parsedSunsetDate))
            {
                result = null;
                failedMember = "sunsetDate";
                return false;
            }

            sunsetDate = parsedSunsetDate.Value;
        }

        result = new(
            status,
            effectiveDate,
            statusReport.AuthenticatorVersion,
            batchCertificate,
            certificate,
            statusReport.Url,
            statusReport.CertificationDescriptor,
            statusReport.CertificateNumber,
            statusReport.CertificationPolicyVersion,
            statusReport.CertificationProfiles,
            statusReport.CertificationRequirementsVersion,
            sunsetDate,
            statusReport.FipsRevision,
            statusReport.FipsPhysicalSecurityLevel);
        failedMember = null;
        return true;
    }

    private static bool TryDecodeAttestationCertificateKeyIdentifiers(string[] attestationCertificateKeyIdentifiers, [NotNullWhen(true)] out byte[][]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (attestationCertificateKeyIdentifiers is null)
        {
            result = null;
            return false;
        }

        result = new byte[attestationCertificateKeyIdentifiers.Length][];
        for (var i = 0; i < attestationCertificateKeyIdentifiers.Length; i++)
        {
            if (!TryDecodeHex(attestationCertificateKeyIdentifiers[i], out var attestationCertificateKeyIdentifier))
            {
                result = null;
                return false;
            }

            result[i] = attestationCertificateKeyIdentifier;
        }

        return true;
    }

    private static bool TryDecodeHex(string input, [NotNullWhen(true)] out byte[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (input is null || input.Length % 2 != 0)
        {
            result = null;
            return false;
        }

        foreach (var ch in input)
        {
            if (!char.IsAsciiHexDigit(ch))
            {
                result = null;
                return false;
            }
        }

        result = Convert.FromHexString(input);
        return true;
    }

    private static bool TryDecodeIso8601Date(string input, [NotNullWhen(true)] out DateTimeOffset? result)
    {
        if (DateTimeOffset.TryParse(input, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            result = parsed;
            return true;
        }

        result = null;
        return false;
    }

    private static bool TryDecodeEnumMemberArray<TEnum>(
        string[] input,
        IEnumMemberAttributeSerializer<TEnum> mapper,
        [NotNullWhen(true)] out TEnum[]? result)
        where TEnum : struct, Enum
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (input is null)
        {
            result = null;
            return false;
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (mapper is null)
        {
            result = null;
            return false;
        }

        result = new TEnum[input.Length];
        for (var i = 0; i < input.Length; i++)
        {
            var inputValue = input[i];
            // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
            if (inputValue is null || !mapper.TryDeserialize(inputValue, out var parsedValue))
            {
                result = null;
                return false;
            }

            result[i] = parsedValue.Value;
        }

        return true;
    }
}

/// <summary>
///     Extension methods for logging the decoding of the FIDO Metadata Service blob.
/// </summary>
public static partial class DefaultFidoMetadataDecoderLoggingExtensions
{
    /// <summary>
    ///     The FIDO Metadata Service blob (no: {No}) doesn't contain the 'entries' member
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the blob.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The FIDO Metadata Service blob (no: {No}) doesn't contain the 'entries' member")]
    public static partial void WarnEntriesMissing(this ILogger logger, long no);

    /// <summary>
    ///     The 'nextUpdate' member of the FIDO Metadata Service blob (no: {No}) contains the value '{NextUpdate}' that is not an ISO-8601 formatted date and will be ignored
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the blob.</param>
    /// <param name="nextUpdate">The value of the 'nextUpdate' member.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'nextUpdate' member of the FIDO Metadata Service blob (no: {No}) contains the value '{NextUpdate}' that is not an ISO-8601 formatted date and will be ignored")]
    public static partial void WarnNextUpdateIgnored(this ILogger logger, long no, string nextUpdate);

    /// <summary>
    ///     The entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was skipped because its '{Member}' member is missing or invalid
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="index">The zero-based index of the entry in the 'entries' array of the blob.</param>
    /// <param name="identifier">The identifier (aaguid, aaid or the first attestationCertificateKeyIdentifiers element) of the entry.</param>
    /// <param name="member">The path of the member of the entry that is missing or invalid.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was skipped because its '{Member}' member is missing or invalid")]
    public static partial void WarnEntrySkipped(this ILogger logger, int index, string identifier, string member);

    /// <summary>
    ///     The entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was skipped because an error occurred during its decoding
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="exception">Exception.</param>
    /// <param name="index">The zero-based index of the entry in the 'entries' array of the blob.</param>
    /// <param name="identifier">The identifier (aaguid, aaid or the first attestationCertificateKeyIdentifiers element) of the entry.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was skipped because an error occurred during its decoding")]
    public static partial void WarnEntrySkippedDueToException(this ILogger logger, Exception exception, int index, string identifier);

    /// <summary>
    ///     The status report #{StatusReportIndex} of the entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was ignored because its 'status' member contains the unknown value '{Status}'
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="index">The zero-based index of the entry in the 'entries' array of the blob.</param>
    /// <param name="identifier">The identifier (aaguid, aaid or the first attestationCertificateKeyIdentifiers element) of the entry.</param>
    /// <param name="statusReportIndex">The zero-based index of the status report in the 'statusReports' array of the entry.</param>
    /// <param name="status">The value of the 'status' member of the status report.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The status report #{StatusReportIndex} of the entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was ignored because its 'status' member contains the unknown value '{Status}'")]
    public static partial void WarnStatusReportIgnored(this ILogger logger, int index, string identifier, int statusReportIndex, string status);

    /// <summary>
    ///     The value #{ValueIndex} ({Value}) of the 'metadataStatement.authenticatorGetInfo.vendorPrototypeConfigCommands' member of the entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was ignored because it is not an unsigned 64-bit integer
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="index">The zero-based index of the entry in the 'entries' array of the blob.</param>
    /// <param name="identifier">The identifier (aaguid, aaid or the first attestationCertificateKeyIdentifiers element) of the entry.</param>
    /// <param name="valueIndex">The zero-based index of the value in the 'vendorPrototypeConfigCommands' array.</param>
    /// <param name="value">The raw JSON text of the ignored value.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The value #{ValueIndex} ({Value}) of the 'metadataStatement.authenticatorGetInfo.vendorPrototypeConfigCommands' member of the entry #{Index} ({Identifier}) of the FIDO Metadata Service blob was ignored because it is not an unsigned 64-bit integer")]
    public static partial void WarnVendorPrototypeConfigCommandIgnored(this ILogger logger, int index, string identifier, int valueIndex, string value);

    /// <summary>
    ///     None of the {Total} entries of the FIDO Metadata Service blob (no: {No}) could be decoded
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the blob.</param>
    /// <param name="total">The total number of entries in the blob.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "None of the {Total} entries of the FIDO Metadata Service blob (no: {No}) could be decoded")]
    public static partial void WarnNoEntriesDecoded(this ILogger logger, long no, int total);

    /// <summary>
    ///     {Decoded} of {Total} entries of the FIDO Metadata Service blob (no: {No}) were decoded, {Skipped} entries were skipped
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="no">The serial number of the blob.</param>
    /// <param name="decoded">The number of successfully decoded entries.</param>
    /// <param name="total">The total number of entries in the blob.</param>
    /// <param name="skipped">The number of skipped entries.</param>
    [LoggerMessage(
        Level = LogLevel.Information,
        Message = "{Decoded} of {Total} entries of the FIDO Metadata Service blob (no: {No}) were decoded, {Skipped} entries were skipped")]
    public static partial void InfoEntriesSkipped(this ILogger logger, long no, int decoded, int total, int skipped);
}
