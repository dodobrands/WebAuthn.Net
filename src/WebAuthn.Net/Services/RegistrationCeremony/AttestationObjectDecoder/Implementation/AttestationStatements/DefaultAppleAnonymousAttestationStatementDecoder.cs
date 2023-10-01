using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.AttestationObjectDecoder.Implementation.AttestationStatements;

public class DefaultAppleAnonymousAttestationStatementDecoder : IAppleAnonymousAttestationStatementDecoder
{
    private readonly ILogger<DefaultAppleAnonymousAttestationStatementDecoder> _logger;

    public DefaultAppleAnonymousAttestationStatementDecoder(ILogger<DefaultAppleAnonymousAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<AppleAnonymousAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg))
        {
            _logger.AppleAnonymousDecodeFailureAlg();
            return Result<AppleAnonymousAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5C))
        {
            _logger.AppleAnonymousDecodeFailureX5C();
            return Result<AppleAnonymousAttestationStatement>.Fail();
        }

        var result = new AppleAnonymousAttestationStatement(alg.Value, x5C);
        return Result<AppleAnonymousAttestationStatement>.Success(result);
    }

    private bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            _logger.AppleAnonymousAlgKeyNotFound();
            value = null;
            return false;
        }

        if (algCbor is not AbstractCborInteger intCborValue)
        {
            _logger.AppleAnonymousAlgValueInvalidDataType();
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intAlg))
        {
            _logger.AppleAnonymousAlgValueOutOfRange();
            value = null;
            return false;
        }

        var alg = (CoseAlgorithm) intAlg.Value;
        if (!Enum.IsDefined(alg))
        {
            _logger.AppleAnonymousAlgValueUnknown(intAlg.Value);
            value = null;
            return false;
        }

        value = alg;
        return true;
    }

    private bool TryDecodeX5C(
        CborMap attStmt,
        [NotNullWhen(true)] out byte[][]? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("x5c"), out var x5CCbor))
        {
            _logger.AppleAnonymousX5CKeyNotFound();
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            _logger.AppleAnonymousX5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                _logger.AppleAnonymousX5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = result;
        return true;
    }
}

public static partial class DefaultAppleAnonymousAttestationStatementDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'alg' value from 'attStmt'")]
    public static partial void AppleAnonymousDecodeFailureAlg(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void AppleAnonymousDecodeFailureX5C(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'alg' key in 'attStmt'")]
    public static partial void AppleAnonymousAlgKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AppleAnonymousAlgValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map is out of range")]
    public static partial void AppleAnonymousAlgValueOutOfRange(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmt' contains an unknown 'alg': {UnknownAlg}")]
    public static partial void AppleAnonymousAlgValueUnknown(this ILogger logger, int unknownAlg);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'x5c' key in 'attStmt'")]
    public static partial void AppleAnonymousX5CKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AppleAnonymousX5CValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void AppleAnonymousX5CValueInvalidElementDataType(this ILogger logger);
}
