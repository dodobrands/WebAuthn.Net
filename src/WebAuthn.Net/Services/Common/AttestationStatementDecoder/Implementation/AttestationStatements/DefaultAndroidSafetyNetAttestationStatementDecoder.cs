using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultAndroidSafetyNetAttestationStatementDecoder : IAndroidSafetyNetAttestationStatementDecoder
{
    private readonly ILogger<DefaultAndroidSafetyNetAttestationStatementDecoder> _logger;

    public DefaultAndroidSafetyNetAttestationStatementDecoder(ILogger<DefaultAndroidSafetyNetAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<AndroidSafetyNetAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);

        if (!TryDecodeVer(attStmt, out var ver))
        {
            _logger.AndroidSafetyNetDecodeFailureVer();
            return Result<AndroidSafetyNetAttestationStatement>.Fail();
        }

        if (!TryDecodeResponse(attStmt, out var response))
        {
            _logger.AndroidSafetyNetDecodeFailureResponse();
            return Result<AndroidSafetyNetAttestationStatement>.Fail();
        }

        var result = new AndroidSafetyNetAttestationStatement(ver, response);
        return Result<AndroidSafetyNetAttestationStatement>.Success(result);
    }

    private bool TryDecodeVer(
        CborMap attStmt,
        [NotNullWhen(true)] out string? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("ver"), out var verCbor))
        {
            _logger.AndroidSafetyNetVerKeyNotFound();
            value = null;
            return false;
        }

        if (verCbor is not CborTextString verCborTextString)
        {
            _logger.AndroidSafetyNetVerValueInvalidDataType();
            value = null;
            return false;
        }

        value = verCborTextString.RawValue;
        return true;
    }

    private bool TryDecodeResponse(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("response"), out var responseCbor))
        {
            _logger.AndroidSafetyNetResponseKeyNotFound();
            value = null;
            return false;
        }

        if (responseCbor is not CborByteString responseCborByteString)
        {
            _logger.AndroidSafetyNetResponseValueInvalidDataType();
            value = null;
            return false;
        }

        value = responseCborByteString.RawValue;
        return true;
    }
}

public static partial class DefaultAndroidSafetyNetAttestationStatementDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'ver' value from 'attStmt'")]
    public static partial void AndroidSafetyNetDecodeFailureVer(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'response' value from 'attStmt'")]
    public static partial void AndroidSafetyNetDecodeFailureResponse(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'ver' key in 'attStmt'")]
    public static partial void AndroidSafetyNetVerKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'ver' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidSafetyNetVerValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'response' key in 'attStmt'")]
    public static partial void AndroidSafetyNetResponseKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'response' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidSafetyNetResponseValueInvalidDataType(this ILogger logger);
}
