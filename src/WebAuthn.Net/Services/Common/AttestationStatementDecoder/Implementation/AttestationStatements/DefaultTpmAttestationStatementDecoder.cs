using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultTpmAttestationStatementDecoder : ITpmAttestationStatementDecoder
{
    private readonly ILogger<DefaultTpmAttestationStatementDecoder> _logger;

    public DefaultTpmAttestationStatementDecoder(ILogger<DefaultTpmAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<TpmAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg))
        {
            _logger.TpmDecodeFailureAlg();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeSig(attStmt, out var sig))
        {
            _logger.TpmDecodeFailureSig();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeVer(attStmt, out var ver))
        {
            _logger.TpmDecodeFailureVer();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5C))
        {
            _logger.TpmDecodeFailureX5C();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodePubArea(attStmt, out var pubArea))
        {
            _logger.TpmDecodeFailurePubArea();
            return Result<TpmAttestationStatement>.Fail();
        }

        if (!TryDecodeCertInfo(attStmt, out var certInfo))
        {
            _logger.TpmDecodeFailureCertInfo();
            return Result<TpmAttestationStatement>.Fail();
        }

        var result = new TpmAttestationStatement(
            ver,
            alg.Value,
            x5C,
            sig,
            certInfo,
            pubArea);
        return Result<TpmAttestationStatement>.Success(result);
    }

    private bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            _logger.TpmAlgKeyNotFound();
            value = null;
            return false;
        }

        if (algCbor is not AbstractCborInteger intCborValue)
        {
            _logger.TpmAlgValueInvalidDataType();
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intAlg))
        {
            _logger.TpmAlgValueOutOfRange();
            value = null;
            return false;
        }

        var alg = (CoseAlgorithm) intAlg.Value;
        if (!Enum.IsDefined(alg))
        {
            _logger.TpmAlgValueUnknown(intAlg.Value);
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
            _logger.TpmSigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            _logger.TpmSigValueInvalidDataType();
            value = null;
            return false;
        }

        value = sigCborByteString.RawValue;
        return true;
    }

    private bool TryDecodeVer(
        CborMap attStmt,
        [NotNullWhen(true)] out string? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("ver"), out var verCbor))
        {
            _logger.TpmVerKeyNotFound();
            value = null;
            return false;
        }

        if (verCbor is not CborTextString verCborTextString)
        {
            _logger.TpmVerValueInvalidDataType();
            value = null;
            return false;
        }

        value = verCborTextString.RawValue;
        return true;
    }

    private bool TryDecodeX5C(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[][]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("x5c"), out var x5CCbor))
        {
            _logger.TpmX5CKeyNotFound();
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            _logger.TpmX5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                _logger.TpmX5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = result;
        return true;
    }

    private bool TryDecodePubArea(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        return TryGetBytesFromByteString(attStmt, "pubArea", out value);
    }

    private bool TryDecodeCertInfo(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        return TryGetBytesFromByteString(attStmt, "certInfo", out value);
    }

    private bool TryGetBytesFromByteString(
        CborMap attStmt,
        string cborMapKey,
        [NotNullWhen(true)] out byte[]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString(cborMapKey), out var cborValue))
        {
            _logger.TpmCantFindCborMapKey(cborMapKey);
            value = null;
            return false;
        }

        if (cborValue is not CborByteString byteStringCborValue)
        {
            _logger.TpmCborMapKeyInvalidDataType(cborMapKey);
            value = null;
            return false;
        }

        value = byteStringCborValue.RawValue;
        return true;
    }
}

public static partial class DefaultTpmAttestationStatementDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'alg' value from 'attStmt'")]
    public static partial void TpmDecodeFailureAlg(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void TpmDecodeFailureSig(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'ver' value from 'attStmt'")]
    public static partial void TpmDecodeFailureVer(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void TpmDecodeFailureX5C(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'pubArea' value from 'attStmt'")]
    public static partial void TpmDecodeFailurePubArea(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'certInfo' value from 'attStmt'")]
    public static partial void TpmDecodeFailureCertInfo(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'alg' key in 'attStmt'")]
    public static partial void TpmAlgKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmAlgValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map is out of range")]
    public static partial void TpmAlgValueOutOfRange(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmt' contains an unknown 'alg': {UnknownAlg}")]
    public static partial void TpmAlgValueUnknown(this ILogger logger, int unknownAlg);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void TpmSigKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'ver' key in 'attStmt'")]
    public static partial void TpmVerKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmSigValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'ver' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmVerValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'x5c' key in 'attStmt'")]
    public static partial void TpmX5CKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void TpmX5CValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void TpmX5CValueInvalidElementDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the key '{CborMapKey}' in 'attStmt'")]
    public static partial void TpmCantFindCborMapKey(this ILogger logger, string cborMapKey);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "An invalid data type is used for the '{CborMapKey}' value in 'attStmt'")]
    public static partial void TpmCborMapKeyInvalidDataType(this ILogger logger, string cborMapKey);
}
