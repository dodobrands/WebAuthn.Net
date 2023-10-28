using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Abstractions;
using WebAuthn.Net.Services.Common.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.Serialization.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Json;

namespace WebAuthn.Net.Services.Common.AttestationObjectDecoder.Implementation;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global")]
public class DefaultAttestationObjectDecoder<TContext> : IAttestationObjectDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    // ReSharper disable once StaticMemberInGenericType
    protected static readonly EnumMemberAttributeMapper<AttestationStatementFormat> AttestationStatementFormatMapper = new();

    public DefaultAttestationObjectDecoder(
        ICborDecoder cborDecoder,
        ILogger<DefaultAttestationObjectDecoder<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(cborDecoder);
        ArgumentNullException.ThrowIfNull(logger);
        CborDecoder = cborDecoder;
        Logger = logger;
    }

    protected ICborDecoder CborDecoder { get; }
    protected ILogger<DefaultAttestationObjectDecoder<TContext>> Logger { get; }

    public virtual Task<Result<AttestationObject>> DecodeAsync(
        TContext context,
        byte[] attestationObject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var mapResult = TryRead(attestationObject);
        if (mapResult.HasError)
        {
            Logger.AttObjReadFailure();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        var attestationObjectCbor = mapResult.Ok;

        if (!TryDecodeAttestationStatementFormat(attestationObjectCbor, out var fmt))
        {
            Logger.AttObjDecodeFailureFmt();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        if (!TryDecodeAttestationStatement(attestationObjectCbor, out var attStmt))
        {
            Logger.AttObjDecodeFailureAttStmt();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        if (!TryDecodeAuthData(attestationObjectCbor, out var authData))
        {
            Logger.AttObjDecodeFailureAuthData();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        var result = new AttestationObject(fmt.Value, attStmt, authData);
        return Task.FromResult(Result<AttestationObject>.Success(result));
    }

    protected virtual Result<CborMap> TryRead(byte[] attestationObject)
    {
        var attestationObjectCborDecode = CborDecoder.Decode(attestationObject);
        if (attestationObjectCborDecode.HasError)
        {
            Logger.AttObjDecodeFailure();
            return Result<CborMap>.Fail();
        }

        var attestationObjectCborRoot = attestationObjectCborDecode.Ok.Root;
        if (attestationObjectCborRoot is not CborMap attestationObjectCborMap)
        {
            Logger.AttObjMustBeCborMap();
            return Result<CborMap>.Fail();
        }

        return Result<CborMap>.Success(attestationObjectCborMap);
    }

    protected virtual bool TryDecodeAttestationStatementFormat(
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

        if (!AttestationStatementFormatMapper.TryGetEnumFromString(fmtCborText.RawValue, out var mappedValue))
        {
            Logger.AttObjFmtValueUnknown(fmtCborText.RawValue);
            value = null;
            return false;
        }

        value = mappedValue.Value;
        return true;
    }

    protected virtual bool TryDecodeAttestationStatement(
        CborMap attestationObjectCborMap,
        [NotNullWhen(true)] out CborMap? value)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectCborMap);
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

    protected virtual bool TryDecodeAuthData(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? decodedValue)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("authData"), out var sigCbor))
        {
            Logger.AttObjAuthDataKeyNotFound();
            decodedValue = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            Logger.AttObjAuthDataValueInvalidDataType();
            decodedValue = null;
            return false;
        }

        decodedValue = sigCborByteString.RawValue;
        return true;
    }
}

public static partial class DefaultAttestationObjectDecoderLoggingExtensions
{
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Error attempting to read the byte representation of 'attestationObject' as a CBOR map")]
    public static partial void AttObjReadFailure(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode 'attestationObject' from CBOR")]
    public static partial void AttObjDecodeFailure(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attestationObject' must be represented as a CBOR map")]
    public static partial void AttObjMustBeCborMap(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'fmt' value from 'attestationObject'")]
    public static partial void AttObjDecodeFailureFmt(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'attStmt' value from 'attestationObject'")]
    public static partial void AttObjDecodeFailureAttStmt(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'authData' value from 'attestationObject'")]
    public static partial void AttObjDecodeFailureAuthData(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'fmt' key in 'attestationObject'")]
    public static partial void AttObjFmtKeyNotFound(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'attStmt' key in 'attestationObject'")]
    public static partial void AttObjAttStmtKeyNotFound(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'authData' key in 'attestationObject'")]
    public static partial void AttObjAuthDataKeyNotFound(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'fmt' value in the 'attestationObject' map contains an invalid data type")]
    public static partial void AttObjFmtValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' value in the 'attestationObject' map contains an invalid data type")]
    public static partial void AttObjAttStmtValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'authData' value in the 'attestationObject' map contains an invalid data type")]
    public static partial void AttObjAuthDataValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'fmt' key in the 'attestationObject' map has an unknown attestation statement format: {UnknownFmt}")]
    public static partial void AttObjFmtValueUnknown(this ILogger logger, string unknownFmt);
}
