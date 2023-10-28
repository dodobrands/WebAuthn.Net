using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultFidoU2FAttestationStatementDecoder : IFidoU2FAttestationStatementDecoder
{
    private readonly ILogger<DefaultFidoU2FAttestationStatementDecoder> _logger;

    public DefaultFidoU2FAttestationStatementDecoder(ILogger<DefaultFidoU2FAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<FidoU2FAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeSig(attStmt, out var sig))
        {
            _logger.FidoU2FDecodeFailureSig();
            return Result<FidoU2FAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5C))
        {
            _logger.FidoU2FDecodeFailureX5C();
            return Result<FidoU2FAttestationStatement>.Fail();
        }

        var result = new FidoU2FAttestationStatement(sig, x5C);
        return Result<FidoU2FAttestationStatement>.Success(result);
    }

    private bool TryDecodeSig(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("sig"), out var sigCbor))
        {
            _logger.FidoU2FSigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            _logger.FidoU2FSigValueInvalidDataType();
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
            _logger.FidoU2Fx5CKeyNotFound();
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            _logger.FidoU2Fx5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                _logger.FidoU2Fx5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = result;
        return true;
    }
}

public static partial class DefaultFidoU2FAttestationStatementDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void FidoU2FDecodeFailureSig(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void FidoU2FDecodeFailureX5C(this ILogger logger);


    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void FidoU2FSigKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void FidoU2FSigValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'x5c' key in 'attStmt'")]
    public static partial void FidoU2Fx5CKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void FidoU2Fx5CValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void FidoU2Fx5CValueInvalidElementDataType(this ILogger logger);
}
