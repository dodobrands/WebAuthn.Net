using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

/// <summary>
///     Default implementation of <see cref="IAndroidSafetyNetAttestationStatementDecoder" />.
/// </summary>
public class DefaultAndroidSafetyNetAttestationStatementDecoder : IAndroidSafetyNetAttestationStatementDecoder
{
    /// <summary>
    ///     Constructs <see cref="DefaultAndroidSafetyNetAttestationStatementDecoder" />.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidSafetyNetAttestationStatementDecoder(ILogger<DefaultAndroidSafetyNetAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAndroidSafetyNetAttestationStatementDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<AndroidSafetyNetAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);

        if (!TryDecodeVer(attStmt, out var ver))
        {
            Logger.AndroidSafetyNetDecodeFailureVer();
            return Result<AndroidSafetyNetAttestationStatement>.Fail();
        }

        if (!TryDecodeResponse(attStmt, out var response))
        {
            Logger.AndroidSafetyNetDecodeFailureResponse();
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
            Logger.AndroidSafetyNetVerKeyNotFound();
            value = null;
            return false;
        }

        if (verCbor is not CborTextString verCborTextString)
        {
            Logger.AndroidSafetyNetVerValueInvalidDataType();
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
            Logger.AndroidSafetyNetResponseKeyNotFound();
            value = null;
            return false;
        }

        if (responseCbor is not CborByteString responseCborByteString)
        {
            Logger.AndroidSafetyNetResponseValueInvalidDataType();
            value = null;
            return false;
        }

        value = responseCborByteString.RawValue;
        return true;
    }
}

/// <summary>
///     Extension methods for logging the Android SafetyNet attestation statement decoder.
/// </summary>
public static partial class DefaultAndroidSafetyNetAttestationStatementDecoderLoggingExtensions
{
    /// <summary>
    ///     Failed to decode the 'ver' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'ver' value from 'attStmt'")]
    public static partial void AndroidSafetyNetDecodeFailureVer(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'response' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'response' value from 'attStmt'")]
    public static partial void AndroidSafetyNetDecodeFailureResponse(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'ver' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'ver' key in 'attStmt'")]
    public static partial void AndroidSafetyNetVerKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'ver' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'ver' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidSafetyNetVerValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'response' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "Failed to find the 'response' key in 'attStmt'")]
    public static partial void AndroidSafetyNetResponseKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'response' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        EventId = default,
        Level = LogLevel.Warning,
        Message = "The 'response' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidSafetyNetResponseValueInvalidDataType(this ILogger logger);
}
