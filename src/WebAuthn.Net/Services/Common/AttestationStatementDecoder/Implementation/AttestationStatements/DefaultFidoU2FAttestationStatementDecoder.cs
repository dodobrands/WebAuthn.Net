using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

/// <summary>
///     Default implementation of <see cref="IFidoU2FAttestationStatementDecoder" />.
/// </summary>
public class DefaultFidoU2FAttestationStatementDecoder : IFidoU2FAttestationStatementDecoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultFidoU2FAttestationStatementDecoder" />.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultFidoU2FAttestationStatementDecoder(ILogger<DefaultFidoU2FAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultFidoU2FAttestationStatementDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<FidoU2FAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeSig(attStmt, out var sig))
        {
            Logger.FidoU2FDecodeFailureSig();
            return Result<FidoU2FAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5C))
        {
            Logger.FidoU2FDecodeFailureX5C();
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
            Logger.FidoU2FSigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            Logger.FidoU2FSigValueInvalidDataType();
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
            Logger.FidoU2Fx5CKeyNotFound();
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            Logger.FidoU2Fx5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                Logger.FidoU2Fx5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        if (result.Length != 1)
        {
            value = null;
            return false;
        }

        value = result;
        return true;
    }
}

/// <summary>
///     Extension methods for logging the FIDO U2F attestation statement decoder.
/// </summary>
public static partial class DefaultFidoU2FAttestationStatementDecoderLoggingExtensions
{
    /// <summary>
    ///     Failed to decode the 'sig' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void FidoU2FDecodeFailureSig(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'x5c' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void FidoU2FDecodeFailureX5C(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'sig' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void FidoU2FSigKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'sig' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void FidoU2FSigValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'x5c' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'x5c' key in 'attStmt'")]
    public static partial void FidoU2Fx5CKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'x5c' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void FidoU2Fx5CValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void FidoU2Fx5CValueInvalidElementDataType(this ILogger logger);
}
