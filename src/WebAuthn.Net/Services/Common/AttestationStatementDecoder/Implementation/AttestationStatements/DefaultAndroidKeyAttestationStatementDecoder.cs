using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementVerifier.Implementation.AndroidKey.Constants;
using WebAuthn.Net.Services.Metrics;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

/// <summary>
///     Default implementation of <see cref="IAndroidKeyAttestationStatementDecoder" />.
/// </summary>
public class DefaultAndroidKeyAttestationStatementDecoder : IAndroidKeyAttestationStatementDecoder
{
    /// <summary>
    ///     The maximum number of certificates accepted in 'x5c': a legitimate attestation trust path (credCert and its certificate chain) is far shorter, and every certificate is loaded and parsed by the verifier before any signature is verified.
    /// </summary>
    protected const int MaxX5CCertificates = 16;

    // the members defined by androidStmtFormat
    private static readonly string[] SyntaxMembers = { "alg", "sig", "x5c" };

    /// <summary>
    ///     Constructs <see cref="DefaultAndroidKeyAttestationStatementDecoder" />.
    /// </summary>
    /// <param name="counters">Counters for registration ceremony metrics, used to count the anomalies found while decoding the attestation statement.</param>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultAndroidKeyAttestationStatementDecoder(
        IRegistrationCeremonyCounters counters,
        ILogger<DefaultAndroidKeyAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(logger);
        Counters = counters;
        Logger = logger;
    }

    /// <summary>
    ///     Counters for registration ceremony metrics, used to count the anomalies found while decoding the attestation statement
    ///     (see <see cref="AndroidKeyAttestationStatementAnomalies" />).
    /// </summary>
    protected IRegistrationCeremonyCounters Counters { get; }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultAndroidKeyAttestationStatementDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<AndroidKeyAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg))
        {
            Logger.AndroidKeyDecodeFailureAlg();
            return Result<AndroidKeyAttestationStatement>.Fail();
        }

        if (!TryDecodeSig(attStmt, out var sig))
        {
            Logger.AndroidKeyDecodeFailureSig();
            return Result<AndroidKeyAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5C))
        {
            Logger.AndroidKeyDecodeFailureX5C();
            return Result<AndroidKeyAttestationStatement>.Fail();
        }

        ReportUnknownMembers(attStmt);
        var result = new AndroidKeyAttestationStatement(alg.Value, sig, x5C);
        return Result<AndroidKeyAttestationStatement>.Success(result);
    }

    /// <summary>
    ///     Reports the members of 'attStmt' that are not defined by the CDDL of the Android Key attestation statement (alg, sig, x5c) with a single Warning log entry
    ///     and the <see cref="AndroidKeyAttestationStatementAnomalies.AttStmtMemberOutsideSyntax" /> anomaly; such members are ignored (tolerated), not rejected.
    /// </summary>
    /// <remarks>
    ///     The members are chosen by the client and are reported before any signature is verified, so their number doesn't multiply the log entries or the anomalies:
    ///     the log entry contains their total number and the keys of at most <c>8</c> of them, and the anomaly is counted once.
    /// </remarks>
    /// <param name="attStmt">The 'attStmt' map.</param>
    protected virtual void ReportUnknownMembers(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        // https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation
        // androidStmtFormat = { alg: COSEAlgorithmIdentifier, sig: bytes, x5c: [ credCert: bytes, * (caCert: bytes) ] }
        // The map is closed, but unknown members are tolerated like in the Packed and TPM attestation statements, and only reported.
        if (AttestationStatementMembersOutsideSyntax.TryDescribe(attStmt, SyntaxMembers, out var count, out var members))
        {
            Logger.AndroidKeyUnknownMembers(count, members);
            Counters.IncrementAttestationStatementAnomaly(AndroidKeyAttestationStatementAnomalies.Format, AndroidKeyAttestationStatementAnomalies.AttStmtMemberOutsideSyntax, true);
        }
    }

    private bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            Logger.AndroidKeyAlgKeyNotFound();
            value = null;
            return false;
        }

        if (algCbor is not AbstractCborInteger intCborValue)
        {
            Logger.AndroidKeyAlgValueInvalidDataType();
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intAlg))
        {
            Logger.AndroidKeyAlgValueOutOfRange();
            value = null;
            return false;
        }

        var alg = (CoseAlgorithm) intAlg.Value;
        if (!Enum.IsDefined(alg))
        {
            Logger.AndroidKeyAlgValueUnknown(intAlg.Value);
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
            Logger.AndroidKeySigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            Logger.AndroidKeySigValueInvalidDataType();
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
            Logger.AndroidKeyX5CKeyNotFound();
            value = null;
            return false;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            Logger.AndroidKeyX5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        // x5c: [ credCert: bytes, * (caCert: bytes) ] - credCert is required
        if (cborArrayItems.Length == 0)
        {
            Logger.AndroidKeyX5CEmptyArray();
            value = null;
            return false;
        }

        if (cborArrayItems.Length > MaxX5CCertificates)
        {
            Logger.AndroidKeyX5CTooManyElements(cborArrayItems.Length, MaxX5CCertificates);
            value = null;
            return false;
        }

        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                Logger.AndroidKeyX5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = result;
        return true;
    }
}

/// <summary>
///     Extension methods for logging the Android Key attestation statement decoder.
/// </summary>
public static partial class DefaultAndroidKeyAttestationStatementDecoderLoggingExtensions
{
    /// <summary>
    ///     Failed to decode the 'alg' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'alg' value from 'attStmt'")]
    public static partial void AndroidKeyDecodeFailureAlg(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'sig' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void AndroidKeyDecodeFailureSig(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'x5c' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void AndroidKeyDecodeFailureX5C(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'alg' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'alg' key in 'attStmt'")]
    public static partial void AndroidKeyAlgKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'alg' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidKeyAlgValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'alg' value in the 'attStmt' map is out of range
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map is out of range")]
    public static partial void AndroidKeyAlgValueOutOfRange(this ILogger logger);

    /// <summary>
    ///     The 'attStmt' contains an unknown 'alg': {UnknownAlg}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="unknownAlg">Unknown 'alg' value.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' contains an unknown 'alg': {UnknownAlg}")]
    public static partial void AndroidKeyAlgValueUnknown(this ILogger logger, int unknownAlg);

    /// <summary>
    ///     Failed to find the 'sig' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void AndroidKeySigKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'sig' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidKeySigValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'x5c' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'x5c' key in 'attStmt'")]
    public static partial void AndroidKeyX5CKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'x5c' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void AndroidKeyX5CValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void AndroidKeyX5CValueInvalidElementDataType(this ILogger logger);

    /// <summary>
    ///     The 'x5c' array in the 'attStmt' contains {Count} elements, which exceeds the maximum of {MaxCount}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of elements in 'x5c'.</param>
    /// <param name="maxCount">The maximum number of elements accepted in 'x5c'.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' array in the 'attStmt' contains {Count} elements, which exceeds the maximum of {MaxCount}")]
    public static partial void AndroidKeyX5CTooManyElements(this ILogger logger, int count, int maxCount);

    /// <summary>
    ///     The 'x5c' array in the 'attStmt' is empty, but it must contain at least credCert
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' array in the 'attStmt' is empty, but it must contain at least credCert")]
    public static partial void AndroidKeyX5CEmptyArray(this ILogger logger);

    /// <summary>
    ///     The 'attStmt' of the Android Key attestation statement contains {Count} member(s) that are not defined by its CDDL (alg, sig, x5c); they are ignored: {Members}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of members outside the syntax.</param>
    /// <param name="members">The keys of at most 8 of those members (see AttestationStatementMembersOutsideSyntax).</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' of the Android Key attestation statement contains {Count} member(s) that are not defined by its CDDL (alg, sig, x5c); they are ignored: {Members}")]
    public static partial void AndroidKeyUnknownMembers(this ILogger logger, int count, string members);
}
