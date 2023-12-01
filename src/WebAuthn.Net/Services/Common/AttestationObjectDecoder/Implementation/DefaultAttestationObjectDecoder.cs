using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.Serialization.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Services.Common.AttestationObjectDecoder.Implementation;

/// <summary>
///     Default implementation of <see cref="IAttestationObjectDecoder" />.
/// </summary>
[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAttestationObjectDecoder : IAttestationObjectDecoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultAttestationObjectDecoder" />.
    /// </summary>
    /// <param name="cborDeserializer">CBOR format deserializer.</param>
    /// <param name="attestationStatementFormatSerializer">Serializer for the <see cref="AttestationStatementFormat" /> enum.</param>
    /// <param name="logger">Logger.</param>
    public DefaultAttestationObjectDecoder(
        ICborDeserializer cborDeserializer,
        IEnumMemberAttributeSerializer<AttestationStatementFormat> attestationStatementFormatSerializer,
        ILogger<DefaultAttestationObjectDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(cborDeserializer);
        ArgumentNullException.ThrowIfNull(attestationStatementFormatSerializer);
        ArgumentNullException.ThrowIfNull(logger);
        CborDeserializer = cborDeserializer;
        AttestationStatementFormatSerializer = attestationStatementFormatSerializer;
        Logger = logger;
    }

    /// <summary>
    ///     CBOR format deserializer.
    /// </summary>
    protected ICborDeserializer CborDeserializer { get; }

    /// <summary>
    ///     Serializer for the <see cref="AttestationStatementFormat" /> enum.
    /// </summary>
    protected IEnumMemberAttributeSerializer<AttestationStatementFormat> AttestationStatementFormatSerializer { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAttestationObjectDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<AttestationObject> Decode(byte[] attestationObject)
    {
        var mapResult = TryRead(attestationObject);
        if (mapResult.HasError)
        {
            Logger.AttObjReadFailure();
            return Result<AttestationObject>.Fail();
        }

        var attestationObjectCbor = mapResult.Ok;

        if (!TryDecodeAttestationStatementFormat(attestationObjectCbor, out var fmt))
        {
            Logger.AttObjDecodeFailureFmt();
            return Result<AttestationObject>.Fail();
        }

        if (!TryDecodeAttestationStatement(attestationObjectCbor, out var attStmt))
        {
            Logger.AttObjDecodeFailureAttStmt();
            return Result<AttestationObject>.Fail();
        }

        if (!TryDecodeAuthData(attestationObjectCbor, out var authData))
        {
            Logger.AttObjDecodeFailureAuthData();
            return Result<AttestationObject>.Fail();
        }

        var result = new AttestationObject(fmt.Value, attStmt, authData);
        return Result<AttestationObject>.Success(result);
    }

    private Result<CborMap> TryRead(byte[] attestationObject)
    {
        var attestationObjectCborDeserialize = CborDeserializer.Deserialize(attestationObject);
        if (attestationObjectCborDeserialize.HasError)
        {
            Logger.AttObjDecodeFailure();
            return Result<CborMap>.Fail();
        }

        var attestationObjectCborRoot = attestationObjectCborDeserialize.Ok.Root;
        if (attestationObjectCborRoot is not CborMap attestationObjectCborMap)
        {
            Logger.AttObjMustBeCborMap();
            return Result<CborMap>.Fail();
        }

        return Result<CborMap>.Success(attestationObjectCborMap);
    }

    private bool TryDecodeAttestationStatementFormat(
        CborMap attestationObjectCborMap,
        [NotNullWhen(true)] out AttestationStatementFormat? value)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectCborMap);
        var dict = attestationObjectCborMap.RawValue;
        if (!dict.TryGetValue(new CborTextString("fmt"), out var fmtCbor))
        {
            Logger.AttObjFmtKeyNotFound();
            value = null;
            return false;
        }

        if (fmtCbor is not CborTextString fmtCborText)
        {
            Logger.AttObjFmtValueInvalidDataType();
            value = null;
            return false;
        }

        if (!AttestationStatementFormatSerializer.TryDeserialize(fmtCborText.RawValue, out var attestationStatementFormat))
        {
            Logger.AttObjFmtValueUnknown(fmtCborText.RawValue);
            value = null;
            return false;
        }

        value = attestationStatementFormat.Value;
        return true;
    }

    private bool TryDecodeAttestationStatement(
        CborMap attestationObjectCborMap,
        [NotNullWhen(true)] out CborMap? value)
    {
        var dict = attestationObjectCborMap.RawValue;
        if (!dict.TryGetValue(new CborTextString("attStmt"), out var attStmtCbor))
        {
            Logger.AttObjAttStmtKeyNotFound();
            value = null;
            return false;
        }

        if (attStmtCbor is not CborMap attStmtCborMap)
        {
            Logger.AttObjAttStmtValueInvalidDataType();
            value = null;
            return false;
        }

        value = attStmtCborMap;
        return true;
    }

    private bool TryDecodeAuthData(
        CborMap attestationObjectCborMap,
        out byte[]? value)
    {
        var dict = attestationObjectCborMap.RawValue;
        if (!dict.TryGetValue(new CborTextString("authData"), out var authDataCbor))
        {
            Logger.AttObjAuthDataKeyNotFound();
            value = null;
            return false;
        }

        if (authDataCbor is not CborByteString authDataCborByteString)
        {
            Logger.AttObjAuthDataValueInvalidDataType();
            value = null;
            return false;
        }

        value = authDataCborByteString.RawValue;
        return true;
    }
}

/// <summary>
///     Extension methods for logging the attestation object decoder.
/// </summary>
public static partial class DefaultAttestationObjectDecoderLoggingExtensions
{
    /// <summary>
    ///     Error attempting to read the byte representation of 'attestationObject' as a CBOR map
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Error attempting to read the byte representation of 'attestationObject' as a CBOR map")]
    public static partial void AttObjReadFailure(this ILogger logger);

    /// <summary>
    ///     Failed to decode 'attestationObject' from CBOR
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode 'attestationObject' from CBOR")]
    public static partial void AttObjDecodeFailure(this ILogger logger);

    /// <summary>
    ///     The 'attestationObject' must be represented as a CBOR map
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attestationObject' must be represented as a CBOR map")]
    public static partial void AttObjMustBeCborMap(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'fmt' value from 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'fmt' value from 'attestationObject'")]
    public static partial void AttObjDecodeFailureFmt(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'attStmt' value from 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'attStmt' value from 'attestationObject'")]
    public static partial void AttObjDecodeFailureAttStmt(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'authData' value from 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'authData' value from 'attestationObject'")]
    public static partial void AttObjDecodeFailureAuthData(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'fmt' key in 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'fmt' key in 'attestationObject'")]
    public static partial void AttObjFmtKeyNotFound(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'attStmt' key in 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'attStmt' key in 'attestationObject'")]
    public static partial void AttObjAttStmtKeyNotFound(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'authData' key in 'attestationObject'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'authData' key in 'attestationObject'")]
    public static partial void AttObjAuthDataKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'fmt' value in the 'attestationObject' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'fmt' value in the 'attestationObject' map contains an invalid data type")]
    public static partial void AttObjFmtValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'attStmt' value in the 'attestationObject' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' value in the 'attestationObject' map contains an invalid data type")]
    public static partial void AttObjAttStmtValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'authData' value in the 'attestationObject' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'authData' value in the 'attestationObject' map contains an invalid data type")]
    public static partial void AttObjAuthDataValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'fmt' key in the 'attestationObject' map has an unknown attestation statement format: {UnknownFmt}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="unknownFmt">Value of the unknown fmt.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'fmt' key in the 'attestationObject' map has an unknown attestation statement format: {UnknownFmt}")]
    public static partial void AttObjFmtValueUnknown(this ILogger logger, string unknownFmt);
}
