using System;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using WebAuthn.Net.Models;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Abstractions.AttestationStatements;
using WebAuthn.Net.Services.Common.AttestationStatementDecoder.Models.AttestationStatements;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree;
using WebAuthn.Net.Services.Serialization.Cbor.Models.Tree.Abstractions;
using WebAuthn.Net.Services.Serialization.Cose.Models.Enums;

namespace WebAuthn.Net.Services.Common.AttestationStatementDecoder.Implementation.AttestationStatements;

/// <summary>
///     Default implementation of <see cref="IPackedAttestationStatementDecoder" />.
/// </summary>
public class DefaultPackedAttestationStatementDecoder : IPackedAttestationStatementDecoder
{
    /// <summary>
    ///     The maximum number of certificates accepted in 'x5c': a legitimate attestation trust path (attestnCert and its intermediate CA certificates) is far shorter, and every certificate is loaded and parsed by the verifier before any signature is verified.
    /// </summary>
    protected const int MaxX5CCertificates = 16;

    // the members defined by packedStmtFormat
    private static readonly string[] SyntaxMembers = { "alg", "sig", "x5c" };

    /// <summary>
    ///     Constructs <see cref="DefaultPackedAttestationStatementDecoder" />.
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <exception cref="ArgumentNullException">Any of the parameters is <see langword="null" /></exception>
    public DefaultPackedAttestationStatementDecoder(ILogger<DefaultPackedAttestationStatementDecoder> logger)
    {
        ArgumentNullException.ThrowIfNull(logger);
        Logger = logger;
    }

    /// <summary>
    ///     Logger.
    /// </summary>
    protected ILogger<DefaultPackedAttestationStatementDecoder> Logger { get; }

    /// <inheritdoc />
    public virtual Result<PackedAttestationStatement> Decode(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        if (!TryDecodeAlg(attStmt, out var alg))
        {
            Logger.PackedDecodeFailureAlg();
            return Result<PackedAttestationStatement>.Fail();
        }

        if (!TryDecodeSig(attStmt, out var sig))
        {
            Logger.PackedDecodeFailureSig();
            return Result<PackedAttestationStatement>.Fail();
        }

        if (!TryDecodeX5C(attStmt, out var x5CResult))
        {
            Logger.PackedDecodeFailureX5C();
            return Result<PackedAttestationStatement>.Fail();
        }

        ReportUnknownMembers(attStmt);
        var x5C = x5CResult.HasValue ? x5CResult.Value : null;
        var result = new PackedAttestationStatement(alg.Value, sig, x5C);
        return Result<PackedAttestationStatement>.Success(result);
    }

    /// <summary>
    ///     Reports the members of 'attStmt' that are not defined by the CDDL of the Packed attestation statement (alg, sig, x5c) with a single Warning log entry; such members are ignored (tolerated), not rejected.
    /// </summary>
    /// <remarks>
    ///     The members are chosen by the client and are reported before any signature is verified, so their number doesn't multiply the log entries:
    ///     the entry contains their total number and the keys of at most <c>8</c> of them.
    /// </remarks>
    /// <param name="attStmt">The 'attStmt' map.</param>
    protected virtual void ReportUnknownMembers(CborMap attStmt)
    {
        ArgumentNullException.ThrowIfNull(attStmt);
        // https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
        // packedStmtFormat = { alg: COSEAlgorithmIdentifier, sig: bytes, x5c: [ attestnCert: bytes, * (caCert: bytes) ] } // { alg: COSEAlgorithmIdentifier, sig: bytes }
        // The map is closed, but unknown members (for example, the 'ecdaaKeyId' of WebAuthn Level 1, whose ECDAA attestation was removed in Level 2) are tolerated for interoperability and only reported.
        if (AttestationStatementMembersOutsideSyntax.TryDescribe(attStmt, SyntaxMembers, out var count, out var members))
        {
            Logger.PackedUnknownMembers(count, members);
        }
    }

    private bool TryDecodeAlg(
        CborMap attStmt,
        [NotNullWhen(true)] out CoseAlgorithm? value)
    {
        var dict = attStmt.RawValue;
        if (!dict.TryGetValue(new CborTextString("alg"), out var algCbor))
        {
            Logger.PackedAlgKeyNotFound();
            value = null;
            return false;
        }

        if (algCbor is not AbstractCborInteger intCborValue)
        {
            Logger.PackedAlgValueInvalidDataType();
            value = null;
            return false;
        }

        if (!intCborValue.TryReadAsInt32(out var intAlg))
        {
            Logger.PackedAlgValueOutOfRange();
            value = null;
            return false;
        }

        var alg = (CoseAlgorithm) intAlg.Value;
        if (!Enum.IsDefined(alg))
        {
            Logger.PackedAlgValueUnknown(intAlg.Value);
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
            Logger.PackedSigKeyNotFound();
            value = null;
            return false;
        }

        if (sigCbor is not CborByteString sigCborByteString)
        {
            Logger.PackedSigValueInvalidDataType();
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
            value = X5CDecodeResult.Empty();
            return true;
        }

        if (x5CCbor is not CborArray x5CborArray)
        {
            Logger.PackedX5CValueInvalidDataType();
            value = null;
            return false;
        }

        var cborArrayItems = x5CborArray.RawValue;
        if (cborArrayItems.Length > MaxX5CCertificates)
        {
            Logger.PackedX5CTooManyElements(cborArrayItems.Length, MaxX5CCertificates);
            value = null;
            return false;
        }

        var result = new byte[cborArrayItems.Length][];
        for (var i = 0; i < cborArrayItems.Length; i++)
        {
            if (cborArrayItems[i] is not CborByteString cborArrayItemByteString)
            {
                Logger.PackedX5CValueInvalidElementDataType();
                value = null;
                return false;
            }

            result[i] = cborArrayItemByteString.RawValue;
        }

        value = X5CDecodeResult.Present(result);
        return true;
    }

    private sealed class X5CDecodeResult
    {
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

        public static X5CDecodeResult Empty()
        {
            return new();
        }
    }
}

/// <summary>
///     Extension methods for logging the Packed attestation statement decoder.
/// </summary>
public static partial class DefaultPackedAttestationStatementDecoderLoggingExtensions
{
    /// <summary>
    ///     Failed to decode the 'alg' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'alg' value from 'attStmt'")]
    public static partial void PackedDecodeFailureAlg(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'sig' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'sig' value from 'attStmt'")]
    public static partial void PackedDecodeFailureSig(this ILogger logger);

    /// <summary>
    ///     Failed to decode the 'x5c' value from 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to decode the 'x5c' value from 'attStmt'")]
    public static partial void PackedDecodeFailureX5C(this ILogger logger);

    /// <summary>
    ///     Failed to find the 'alg' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'alg' key in 'attStmt'")]
    public static partial void PackedAlgKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'alg' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map contains an invalid data type")]
    public static partial void PackedAlgValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'alg' value in the 'attStmt' map is out of range
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'alg' value in the 'attStmt' map is out of range")]
    public static partial void PackedAlgValueOutOfRange(this ILogger logger);

    /// <summary>
    ///     The 'attStmt' contains an unknown 'alg': {UnknownAlg}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="unknownAlg">Unknown 'alg' value.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' contains an unknown 'alg': {UnknownAlg}")]
    public static partial void PackedAlgValueUnknown(this ILogger logger, int unknownAlg);

    /// <summary>
    ///     Failed to find the 'sig' key in 'attStmt'
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "Failed to find the 'sig' key in 'attStmt'")]
    public static partial void PackedSigKeyNotFound(this ILogger logger);

    /// <summary>
    ///     The 'sig' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'sig' value in the 'attStmt' map contains an invalid data type")]
    public static partial void PackedSigValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     The 'x5c' value in the 'attStmt' map contains an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' value in the 'attStmt' map contains an invalid data type")]
    public static partial void PackedX5CValueInvalidDataType(this ILogger logger);

    /// <summary>
    ///     One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type
    /// </summary>
    /// <param name="logger">Logger.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "One of the 'x5c' array elements in the 'attStmt' contains a CBOR element with an invalid data type")]
    public static partial void PackedX5CValueInvalidElementDataType(this ILogger logger);

    /// <summary>
    ///     The 'x5c' array in the 'attStmt' contains {Count} elements, which exceeds the maximum of {MaxCount}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of elements in 'x5c'.</param>
    /// <param name="maxCount">The maximum number of elements accepted in 'x5c'.</param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'x5c' array in the 'attStmt' contains {Count} elements, which exceeds the maximum of {MaxCount}")]
    public static partial void PackedX5CTooManyElements(this ILogger logger, int count, int maxCount);

    /// <summary>
    ///     The 'attStmt' of the Packed attestation statement contains {Count} member(s) that are not defined by its CDDL (alg, sig, x5c); they are ignored: {Members}
    /// </summary>
    /// <param name="logger">Logger.</param>
    /// <param name="count">The number of the members that are not defined by the CDDL.</param>
    /// <param name="members">
    ///     The keys of the first (at most 8) such members, separated by commas: a text key in quotes (truncated to 64 characters, with every control character replaced by '?'),
    ///     a key of any other data type as its CBOR data type in angle brackets. If there are more members, the list ends with ", ...".
    /// </param>
    [LoggerMessage(
        Level = LogLevel.Warning,
        Message = "The 'attStmt' of the Packed attestation statement contains {Count} member(s) that are not defined by its CDDL (alg, sig, x5c); they are ignored: {Members}")]
    public static partial void PackedUnknownMembers(this ILogger logger, int count, string members);
}
