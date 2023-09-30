using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Format.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Serialization.Cbor.AttestationObject.Implementation.AttestationStatements;

public class DefaultAndroidKeyAttestationStatementDecoder : IAndroidKeyAttestationStatementDecoder
{
    private readonly ILogger<DefaultAndroidKeyAttestationStatementDecoder> _logger;

    public DefaultAndroidKeyAttestationStatementDecoder(ILogger<DefaultAndroidKeyAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<AndroidKeyAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg))
        {
            _logger.AndroidKeyDecodeFailureAlg();
            return Result<AndroidKeyAttestationStatement>.Fail();
        }

        if (!TryDecodeSig(attStmt, out var sig))
        {
            _logger.AndroidKeyDecodeFailureSig();
            return Result<AndroidKeyAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5C))
        {
            _logger.AndroidKeyDecodeFailureX5C();
            return Result<AndroidKeyAttestationStatement>.Fail();
        }

        var result = new AndroidKeyAttestationStatement(alg.Value, sig, x5C);
        return Result<AndroidKeyAttestationStatement>.Success(result);
    }

    private bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            _logger.AndroidKeyAlgKeyNotFound();
            value = null;
            return false;
        }

        if (algCbor is not AbstractCborInteger intCborValue)
        {
            _logger.AndroidKeyAlgValueInvalidDataType();
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intAlg))
        {
            _logger.AndroidKeyAlgValueOutOfRange();
            value = null;
            return false;
        }

        var alg = (CoseAlgorithm) intAlg.Value;
        if (!Enum.IsDefined(alg))
        {
            _logger.AndroidKeyAlgValueUnknown(intAlg.Value);
            value = null;
            return false;
        }

        value = alg;
        return true;
    }

    private bool TryDecodeSig(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("sig"), out var sigCbor))
        {
            _logger.AndroidKeySigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            _logger.AndroidKeySigValueInvalidDataType();
            value = null;
            return false;
        }

        value = sigCborByteString.RawValue;
        return true;
    }

    private bool TryDecodeX5C(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[][]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("x5c"), out var x5CCbor))
        {
            _logger.AndroidKeyX5CKeyNotFound();
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            _logger.AndroidKeyX5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                _logger.AndroidKeyX5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = result;
        return true;
    }
}

public static partial class DefaultAndroidKeyAttestationStatementDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'alg' value from 'attStmt'")]
    public static partial void AndroidKeyDecodeFailureAlg(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void AndroidKeyDecodeFailureSig(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void AndroidKeyDecodeFailureX5C(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'alg' key in 'attStmt'")]
    public static partial void AndroidKeyAlgKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidKeyAlgValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map is out of range")]
    public static partial void AndroidKeyAlgValueOutOfRange(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmt' contains an unknown 'alg': {UnknownAlg}")]
    public static partial void AndroidKeyAlgValueUnknown(this ILogger logger, int unknownAlg);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void AndroidKeySigKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidKeySigValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'x5c' key in 'attStmt'")]
    public static partial void AndroidKeyX5CKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidKeyX5CValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void AndroidKeyX5CValueInvalidElementDataType(this ILogger logger);
}
