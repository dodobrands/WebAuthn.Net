using System;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Enums;
using WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataProvider.Protocol.Json;
using WebAuthn.Net.Services.Serialization.Json;
using WebAuthn.Net.Services.Static;
using Version = WebAuthn.Net.Services.FidoMetadata.Models.FidoMetadataDecoder.Version;

namespace WebAuthn.Net.Services.FidoMetadata.Implementation.FidoMetadataDecoder;

/// <summary>
///     Default implementation of <see cref="IFidoMetadataDecoder" />.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultFidoMetadataDecoder : IFidoMetadataDecoder
{
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
        IEnumMemberAttributeSerializer<TransactionConfirmationDisplayType> transactionConfirmationDisplayTypeSerializer)
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
        UserVerificationMethodSerializer = userVerificationMethodSerializer;
        ProtocolFamilySerializer = protocolFamilySerializer;
        AuthenticationAlgorithmSerializer = authenticationAlgorithmSerializer;
        PublicKeyRepresentationFormatSerializer = publicKeyRepresentationFormatSerializer;
        AuthenticatorAttestationTypeSerializer = authenticatorAttestationTypeSerializer;
        KeyProtectionTypeSerializer = keyProtectionTypeSerializer;
        MatcherProtectionTypeSerializer = matcherProtectionTypeSerializer;
        AuthenticatorAttachmentHintSerializer = authenticatorAttachmentHintSerializer;
        TransactionConfirmationDisplayTypeSerializer = transactionConfirmationDisplayTypeSerializer;
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

    /// <inheritdoc />
    public virtual Result<MetadataBlobPayload> Decode(MetadataBLOBPayloadJSON json)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (json is null)
        {
            return Result<MetadataBlobPayload>.Fail();
        }

        if (!TryDecodeIso8601Date(json.NextUpdate, out var nextUpdate))
        {
            return Result<MetadataBlobPayload>.Fail();
        }

        if (!TryDecodeEntries(json.Entries, out var entries))
        {
            return Result<MetadataBlobPayload>.Fail();
        }

        var result = new MetadataBlobPayload(
            json.LegalHeader,
            json.No,
            nextUpdate.Value,
            entries);
        return Result<MetadataBlobPayload>.Success(result);
    }

    private bool TryDecodeEntries(MetadataBLOBPayloadEntryJSON[] entries, [NotNullWhen(true)] out MetadataBlobPayloadEntry[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (entries is null)
        {
            result = null;
            return false;
        }

        result = new MetadataBlobPayloadEntry[entries.Length];
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            if (!TryDecodeEntry(entry, out var decodedEntry))
            {
                result = null;
                return false;
            }

            result[i] = decodedEntry;
        }

        return true;
    }

    private bool TryDecodeEntry(MetadataBLOBPayloadEntryJSON entry, [NotNullWhen(true)] out MetadataBlobPayloadEntry? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (entry is null)
        {
            result = null;
            return false;
        }

        Guid? aaguid = null;
        if (entry.Aaguid is not null)
        {
            if (!Guid.TryParse(entry.Aaguid, out var parsedAaguid))
            {
                result = null;
                return false;
            }

            aaguid = parsedAaguid;
        }

        if (entry.Aaguid is null && entry.Aaid is null && entry.AttestationCertificateKeyIdentifiers is null)
        {
            result = null;
            return false;
        }

        byte[][]? attestationCertificateKeyIdentifiers = null;
        if (entry.AttestationCertificateKeyIdentifiers is not null)
        {
            attestationCertificateKeyIdentifiers = new byte[entry.AttestationCertificateKeyIdentifiers.Length][];
            for (var i = 0; i < entry.AttestationCertificateKeyIdentifiers.Length; i++)
            {
                attestationCertificateKeyIdentifiers[i] = Convert.FromHexString(entry.AttestationCertificateKeyIdentifiers[i]);
            }
        }

        MetadataStatement? metadataStatement = null;
        if (entry.MetadataStatement is not null && !TryDecodeMetadataStatement(entry.MetadataStatement, out metadataStatement))
        {
            result = null;
            return false;
        }

        BiometricStatusReport[]? biometricStatusReports = null;
        if (entry.BiometricStatusReports is not null && !TryDecodeBiometricStatusReports(entry.BiometricStatusReports, out biometricStatusReports))
        {
            result = null;
            return false;
        }

        if (!TryDecodeStatusReports(entry.StatusReports, out var statusReports))
        {
            result = null;
            return false;
        }

        if (!TryDecodeIso8601Date(entry.TimeOfLastStatusChange, out var timeOfLastStatusChange))
        {
            result = null;
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
        return true;
    }

    private bool TryDecodeMetadataStatement(MetadataStatementJSON metadataStatement, [NotNullWhen(true)] out MetadataStatement? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (metadataStatement is null)
        {
            result = null;
            return false;
        }

        Guid? aaguid = null;
        if (metadataStatement.Aaguid is not null)
        {
            if (!Guid.TryParse(metadataStatement.Aaguid, out var parsedAaguid))
            {
                result = null;
                return false;
            }

            aaguid = parsedAaguid;
        }

        byte[][]? attestationCertificateKeyIdentifiers = null;
        if (metadataStatement.AttestationCertificateKeyIdentifiers is not null)
        {
            attestationCertificateKeyIdentifiers = new byte[metadataStatement.AttestationCertificateKeyIdentifiers.Length][];
            for (var i = 0; i < metadataStatement.AttestationCertificateKeyIdentifiers.Length; i++)
            {
                attestationCertificateKeyIdentifiers[i] = Convert.FromHexString(metadataStatement.AttestationCertificateKeyIdentifiers[i]);
            }
        }

        if (!ProtocolFamilySerializer.TryDeserialize(metadataStatement.ProtocolFamily, out var protocolFamily))
        {
            result = null;
            return false;
        }

        if (!TryDecodeUpv(metadataStatement.Upv, out var upv))
        {
            result = null;
            return false;
        }

        if (!TryDecodeAuthenticationAlgorithms(metadataStatement.AuthenticationAlgorithms, out var authenticationAlgorithms))
        {
            result = null;
            return false;
        }

        if (!TryDecodePublicKeyAlgAndEncodings(metadataStatement.PublicKeyAlgAndEncodings, out var publicKeyAlgAndEncodings))
        {
            result = null;
            return false;
        }

        if (!TryDecodeAttestationTypes(metadataStatement.AttestationTypes, out var attestationTypes))
        {
            result = null;
            return false;
        }

        if (!TryDecodeUserVerificationDetails(metadataStatement.UserVerificationDetails, out var userVerificationDetails))
        {
            result = null;
            return false;
        }

        if (!TryDecodeKeyProtection(metadataStatement.KeyProtection, out var keyProtection))
        {
            result = null;
            return false;
        }

        if (!TryDecodeMatcherProtection(metadataStatement.MatcherProtection, out var matcherProtection))
        {
            result = null;
            return false;
        }

        AuthenticatorAttachmentHint[]? attachmentHint = null;
        if (metadataStatement.AttachmentHint is not null && !TryDecodeAttachmentHint(metadataStatement.AttachmentHint, out attachmentHint))
        {
            result = null;
            return false;
        }

        if (!TryDecodeTcDisplay(metadataStatement.TcDisplay, out var tcDisplay))
        {
            result = null;
            return false;
        }

        DisplayPngCharacteristicsDescriptor[]? tcDisplayPngCharacteristics = null;
        if (metadataStatement.TcDisplayPNGCharacteristics is not null && !TryDecodeTcDisplayPngCharacteristics(metadataStatement.TcDisplayPNGCharacteristics, out tcDisplayPngCharacteristics))
        {
            result = null;
            return false;
        }

        if (!TryDecodeAttestationRootCertificates(metadataStatement.AttestationRootCertificates, out var attestationRootCertificates))
        {
            result = null;
            return false;
        }

        EcdaaTrustAnchor[]? ecdaaTrustAnchors = null;
        if (metadataStatement.EcdaaTrustAnchors is not null && !TryDecodeEcdaaTrustAnchors(metadataStatement.EcdaaTrustAnchors, out ecdaaTrustAnchors))
        {
            result = null;
            return false;
        }

        ExtensionDescriptor[]? supportedExtensions = null;
        if (metadataStatement.SupportedExtensions is not null && !TryDecodeSupportedExtensions(metadataStatement.SupportedExtensions, out supportedExtensions))
        {
            result = null;
            return false;
        }

        AuthenticatorGetInfo? authenticatorGetInfo = null;
        if (metadataStatement.AuthenticatorGetInfo is not null && !TryDecodeAuthenticatorGetInfo(metadataStatement.AuthenticatorGetInfo, out authenticatorGetInfo))
        {
            result = null;
            return false;
        }

        result = new(
            metadataStatement.LegalHeader,
            metadataStatement.Aaid,
            aaguid,
            attestationCertificateKeyIdentifiers,
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
            supportedExtensions,
            authenticatorGetInfo);
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
            if (!Base64Raw.TryDecode(attestationRootCertificates[i].Trim(), out var attestationRootCertificate))
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

    private static bool TryDecodeAuthenticatorGetInfo(AuthenticatorGetInfoJSON authenticatorGetInfo, [NotNullWhen(true)] out AuthenticatorGetInfo? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (authenticatorGetInfo is null)
        {
            result = null;
            return false;
        }

        if (!Guid.TryParse(authenticatorGetInfo.Aaguid, out var aaguid))
        {
            result = null;
            return false;
        }

        result = new(
            authenticatorGetInfo.Versions,
            authenticatorGetInfo.Extensions,
            aaguid,
            authenticatorGetInfo.Options,
            authenticatorGetInfo.MaxMsgSize,
            authenticatorGetInfo.PinProtocols);
        return true;
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

    private static bool TryDecodeStatusReports(StatusReportJSON[] statusReports, [NotNullWhen(true)] out StatusReport[]? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (statusReports is null)
        {
            result = null;
            return false;
        }

        result = new StatusReport[statusReports.Length];
        for (var i = 0; i < statusReports.Length; i++)
        {
            if (!TryDecodeStatusReport(statusReports[i], out var statusReport))
            {
                result = null;
                return false;
            }

            result[i] = statusReport;
        }

        return true;
    }

    private static bool TryDecodeStatusReport(StatusReportJSON statusReport, [NotNullWhen(true)] out StatusReport? result)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (statusReport is null)
        {
            result = null;
            return false;
        }

        if (!Enum.TryParse<AuthenticatorStatus>(statusReport.Status, false, out var status))
        {
            result = null;
            return false;
        }

        DateTimeOffset? effectiveDate = null;
        if (statusReport.EffectiveDate is not null && !TryDecodeIso8601Date(statusReport.EffectiveDate, out effectiveDate))
        {
            result = null;
            return false;
        }

        byte[]? certificate = null;
        if (statusReport.Certificate is not null)
        {
            if (!Base64Raw.TryDecode(statusReport.Certificate, out var statusReportCertificate))
            {
                result = null;
                return false;
            }

            certificate = statusReportCertificate;
        }

        result = new(
            status,
            effectiveDate,
            statusReport.AuthenticatorVersion,
            certificate,
            statusReport.Url,
            statusReport.CertificationDescriptor,
            statusReport.CertificateNumber,
            statusReport.CertificationPolicyVersion,
            statusReport.CertificationRequirementsVersion);
        return true;
    }

    private static bool TryDecodeIso8601Date(string input, [NotNullWhen(true)] out DateTimeOffset? result)
    {
        if (DateTimeOffset.TryParse(input, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed))
        {
            result = new DateTimeOffset(parsed.Ticks, TimeSpan.Zero);
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
            if (!mapper.TryDeserialize(input[i], out var parsedValue))
            {
                result = null;
                return false;
            }

            result[i] = parsedValue.Value;
        }

        return true;
    }
}
