using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Cryptography.Cose.Models.Enums;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;

namespace WebAuthn.Net.Services.RegistrationCeremony.Services.AttestationStatementDecoder.Implementation.AttestationStatements;

public class DefaultPackedAttestationStatementDecoder : IPackedAttestationStatementDecoder
{
    private readonly ILogger<DefaultPackedAttestationStatementDecoder> _logger;

    public DefaultPackedAttestationStatementDecoder(ILogger<DefaultPackedAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        _logger = logger;
    }

    public Result<PackedAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg))
        {
            _logger.PackedDecodeFailureAlg();
            return Result<PackedAttestationStatement>.Fail();
        }

        if (!TryDecodeSig(attStmt, out var sig))
        {
            _logger.PackedDecodeFailureSig();
            return Result<PackedAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5CResult))
        {
            _logger.PackedDecodeFailureX5C();
            return Result<PackedAttestationStatement>.Fail();
        }

        var x5C = x5CResult.HasValue ? x5CResult.Value : null;
        var result = new PackedAttestationStatement(alg.Value, sig, x5C);
        return Result<PackedAttestationStatement>.Success(result);
    }

    private bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            _logger.PackedAlgKeyNotFound();
            value = null;
            return false;
        }

        if (algCbor is not AbstractCborInteger intCborValue)
        {
            _logger.PackedAlgValueInvalidDataType();
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intAlg))
        {
            _logger.PackedAlgValueOutOfRange();
            value = null;
            return false;
        }

        var alg = (CoseAlgorithm) intAlg.Value;
        if (!Enum.IsDefined(alg))
        {
            _logger.PackedAlgValueUnknown(intAlg.Value);
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
            _logger.PackedSigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            _logger.PackedSigValueInvalidDataType();
            value = null;
            return false;
        }

        value = sigCborByteString.RawValue;
        return true;
    }

    private bool TryDecodeX5C(
        CborMap attStmt,
        [NotNullWhen(true)] out X5CDecodeResult? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("x5c"), out var x5CCbor))
        {
            value = X5CDecodeResult.Empty;
            return true;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            _logger.PackedX5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                _logger.PackedX5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = X5CDecodeResult.Present(result);
        return true;
    }

    private class X5CDecodeResult
    {
        public static readonly X5CDecodeResult Empty = new();

        private X5CDecodeResult(byte[][] value)
        {
            HasValue = true;
            Value = value;
        }

        private X5CDecodeResult()
        {
            HasValue = false;
        }

        public byte[][]? Value { get; }

        [MemberNotNullWhen(true, nameof(Value))]
        public bool HasValue { get; }

        public static X5CDecodeResult Present(byte[][] value)
        {
            return new(value);
        }
    }
}

public static partial class DefaultPackedAttestationStatementDecoderLoggingExtensions
{
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'alg' value from 'attStmt'")]
    public static partial void PackedDecodeFailureAlg(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void PackedDecodeFailureSig(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void PackedDecodeFailureX5C(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'alg' key in 'attStmt'")]
    public static partial void PackedAlgKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    public static partial void PackedAlgValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map is out of range")]
    public static partial void PackedAlgValueOutOfRange(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'attStmt' contains an unknown 'alg': {UnknownAlg}")]
    public static partial void PackedAlgValueUnknown(this ILogger logger, int unknownAlg);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void PackedSigKeyNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void PackedSigValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void PackedX5CValueInvalidDataType(this ILogger logger);

    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void PackedX5CValueInvalidElementDataType(this ILogger logger);
}
