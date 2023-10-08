using System;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Models.Abstractions;
using WebAuthn.Net.Models.Protocol.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Abstractions;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Models.AttestationStatements.Abstractions;
using WebAuthn.Net.Services.Serialization.Cbor;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationObjectDecoder.Implementation;

public class DefaultAttestationObjectDecoder<TContext> : IAttestationObjectDecoder<TContext>
    where TContext : class, IWebAuthnContext
{
    private readonly IAttestationStatementDecoder _attStmtDecoder;
    private readonly IAuthenticatorDataDecoder _authDataDecoder;
    private readonly ICborDecoder _cborDecoder;
    private readonly ILogger<DefaultAttestationObjectDecoder<TContext>> _logger;

    public DefaultAttestationObjectDecoder(
        ICborDecoder cborDecoder,
        IAttestationStatementDecoder attStmtDecoder,
        IAuthenticatorDataDecoder authDataDecoder,
        ILogger<DefaultAttestationObjectDecoder<TContext>> logger)
    {
        ArgumentNullException.ThrowIfNull(cborDecoder);
        ArgumentNullException.ThrowIfNull(attStmtDecoder);
        ArgumentNullException.ThrowIfNull(authDataDecoder);
        ArgumentNullException.ThrowIfNull(logger);
        _cborDecoder = cborDecoder;
        _attStmtDecoder = attStmtDecoder;
        _authDataDecoder = authDataDecoder;
        _logger = logger;
    }

    public virtual Task<Result<AttestationObject>> DecodeAsync(
        TContext context,
        byte[] attestationObject,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var mapResult = TryRead(attestationObject);
        if (mapResult.HasError)
        {
            _logger.AttObjReadFailure();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        var attestationObjectCbor = mapResult.Ok;

        if (!TryDecodeAttestationStatementFormat(attestationObjectCbor, out var fmt))
        {
            _logger.AttObjDecodeFailureFmt();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        if (!TryDecodeAttestationStatement(attestationObjectCbor, fmt.Value, out var attStmt))
        {
            _logger.AttObjDecodeFailureAttStmt();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        if (!TryDecodeAuthData(attestationObjectCbor, out var authData))
        {
            _logger.AttObjDecodeFailureAuthData();
            return Task.FromResult(Result<AttestationObject>.Fail());
        }

        var result = new AttestationObject(fmt.Value, attStmt, authData);
        return Task.FromResult(Result<AttestationObject>.Success(result));
    }

    protected virtual Result<CborMap> TryRead(byte[] attestationObject)
    {
        var attestationObjectCborDecode = _cborDecoder.Decode(attestationObject);
        if (attestationObjectCborDecode.HasError)
        {
            _logger.AttObjDecodeFailure();
            return Result<CborMap>.Fail();
        }

        var attestationObjectCborRoot = attestationObjectCborDecode.Ok.Root;
        if (attestationObjectCborRoot is not CborMap attestationObjectCborMap)
        {
            _logger.AttObjMustBeCborMap();
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
            _logger.AttObjFmtKeyNotFound();
            value = null;
            return false;
        }

        if (fmtCbor is not CborTextString fmtCborText)
        {
            _logger.AttObjFmtValueInvalidDataType();
            value = null;
            return false;
        }

        switch (fmtCborText.RawValue)
        {
            case "none":
                value = AttestationStatementFormat.None;
                return true;
            case "packed":
                value = AttestationStatementFormat.Packed;
                return true;
            case "tpm":
                value = AttestationStatementFormat.Tpm;
                return true;
            case "android-key":
                value = AttestationStatementFormat.AndroidKey;
                return true;
            case "android-safetynet":
                value = AttestationStatementFormat.AndroidSafetynet;
                return true;
            case "fido-u2f":
                value = AttestationStatementFormat.FidoU2F;
                return true;
            case "apple":
                value = AttestationStatementFormat.AppleAnonymous;
                return true;
            default:
                value = null;
                _logger.AttObjFmtValueUnknown(fmtCborText.RawValue);
                return false;
        }
    }

    protected virtual bool TryDecodeAttestationStatement(
        CborMap attestationObjectCborMap,
        AttestationStatementFormat format,
        [NotNullWhen(true)] out AbstractAttestationStatement? value)
    {
        ArgumentNullException.ThrowIfNull(attestationObjectCborMap);
        var dict = attestationObjectCborMap.RawValue;
        if (!dict.TryGetValue(new CborTextString("attStmt"), out var attStmtCbor))
        {
            _logger.AttObjAttStmtKeyNotFound();
            value = null;
            return false;
        }

        if (attStmtCbor is not CborMap attStmtCborMap)
        {
            _logger.AttObjAttStmtValueInvalidDataType();
            value = null;
            return false;
        }

        var decodeResult = _attStmtDecoder.Decode(attStmtCborMap, format);
        if (decodeResult.HasError)
        {
            value = null;
            return false;
        }

        value = decodeResult.Ok;
        return true;
    }

    protected virtual bool TryDecodeAuthData(
        CborMap attStmt,
        [NotNullWhen(true)] out AuthenticatorData? decodedValue)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("authData"), out var sigCbor))
        {
            _logger.AttObjAuthDataKeyNotFound();
            decodedValue = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            _logger.AttObjAuthDataValueInvalidDataType();
            decodedValue = null;
            return false;
        }

        var decodeResult = _authDataDecoder.Decode(sigCborByteString.RawValue);
        if (decodeResult.HasError)
        {
            decodedValue = null;
            return false;
        }

        decodedValue = decodeResult.Ok;
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
